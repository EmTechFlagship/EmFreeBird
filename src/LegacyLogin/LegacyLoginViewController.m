#import "LegacyLoginViewController.h"
#import <WebKit/WebKit.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <ifaddrs.h>
#import <net/if.h>
#import <netinet/in.h>
#import <objc/message.h>
#import <objc/runtime.h>
#import <sys/socket.h>
#import "Core/BHTBundle.h"
#import "Headers/TFNHeaders.h"

// Password login (no reset), matching 9.67's built-in sign-in:
//   1. Generate ui_metrics from x.com/i/js_inst (anti-bot token).
//   2. xauth_password -> OAuth token directly, or a 2FA challenge.
//   3. On 2FA, present the app's T1LoginChallengeFactory web challenge, which polls
//   xauth_challenge.
//   4. Add the account and switch to it.

typedef void (^CmdCompletion)(BOOL success, id response, id parseError);

typedef id (*PwInitIMP)(id, SEL, id context, id accountID, id authContext, id identifier,
                        id password, id simCountryCode, id httpConfig, BOOL supportOneFactor,
                        id knownDeviceToken, id uiMetrics, id authTokenStorage, id source,
                        id builder, id completion);

#pragma mark - Runtime helpers

static long long UserId(id resp, SEL sel) {
    if (!resp || ![resp respondsToSelector:sel]) {
        return 0;
    }
    return ((long long (*)(id, SEL))objc_msgSend)(resp, sel);
}

static id Perform0(id target, SEL selector) {
    if (!target || ![target respondsToSelector:selector]) {
        return nil;
    }
    return ((id (*)(id, SEL))objc_msgSend)(target, selector);
}

// API error 243 ("client not privileged"/too many attempts) is likely rate limiting
// and can be bypassed by switching on a VPN.
static BOOL IsRateLimit(id error) {
    if (![error isKindOfClass:[NSError class]]) {
        return NO;
    }

    NSError* e = error;
    if (e.code == 243) {
        return YES;
    }

    for (id value in [e.userInfo allValues]) {
        if ([value isKindOfClass:[NSNumber class]] && [value integerValue] == 243) {
            return YES;
        }
    }

    return [[e description] rangeOfString:@"243"].location != NSNotFound;
}

#pragma mark - Command / service accessors

static id GuestAccountID(void) {
    void* sym = dlsym(RTLD_DEFAULT, "TFSTwitterAPIGuestAccountID");
    return sym ? (__bridge id)(*(void**)sym) : nil;
}

static id Loader(void) {
    return Perform0(objc_getClass("TFSTwitterServiceRunner"), @selector(APICommandLoader));
}

static id Context(void) {
    return Perform0(objc_getClass("TFSTwitterServiceRunner"), @selector(APICommandContext));
}

static id Builder(const char* className) {
    Class cls = objc_getClass(className);
    return cls ? [[cls alloc] init] : nil;
}

static id Storage(void) {
    Class cls = objc_getClass("T1OnboardingAuthTokenStorage");
    return cls ? [[cls alloc] init] : nil;
}

static id KnownDeviceToken(void) {
    return Perform0(objc_getClass("TFNTwitterAccount"), @selector(knownDeviceToken));
}

static id HTTPConfig(void) {
    Class cls = objc_getClass("TNUServiceHTTPConfiguration");
    SEL sel = @selector(configurationForForegroundRetriableRequest);
    if (!cls || ![cls respondsToSelector:sel]) {
        return nil;
    }

    return ((id (*)(id, SEL))objc_msgSend)(cls, sel);
}

#pragma mark - Account finalization

static void RegisterAccount(id account) {
    if (!account) {
        return;
    }

    Class twitterCls = objc_getClass("TFNTwitter");
    id shared = Perform0(twitterCls, @selector(sharedTwitter));
    id service = Perform0(shared, @selector(accountService));

    @try {
        if (service && [service respondsToSelector:@selector(addAccount:)]) {
            ((void (*)(id, SEL, id))objc_msgSend)(service, @selector(addAccount:), account);
        }

        if ([twitterCls respondsToSelector:@selector(saveSharedTwitter)]) {
            ((void (*)(id, SEL))objc_msgSend)(twitterCls, @selector(saveSharedTwitter));
        }

        if ([account respondsToSelector:@selector(refreshForced:source:)]) {
            ((void (*)(id, SEL, BOOL, unsigned long long))objc_msgSend)(
                account, @selector(refreshForced:source:), NO, 0);
        }

        Class notifCls = objc_getClass("TFSAccountNotification");
        id name = Perform0(notifCls, @selector(TFSAccountsDidChange));
        if ([name isKindOfClass:[NSString class]]) {
            [[NSNotificationCenter defaultCenter] postNotificationName:name object:shared userInfo:nil];
        }
    } @catch (NSException* ex) {
    }
}

static void SwitchToAccount(id account) {
    id host = Perform0(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
    if (host && [host respondsToSelector:@selector(viewAccount:animated:)]) {
        ((void (*)(id, SEL, id, BOOL))objc_msgSend)(host, @selector(viewAccount:animated:), account,
                                                    YES);
    }
}

#pragma mark - Error parsing / localization helpers

// Best-effort localization lookup: own bundle first, then Twitter's bundle,
// then the supplied fallback (so a renamed/missing Twitter key never leaks
// a raw key like "OK_ACTION_LABEL" into the UI, as seen in the login alert).
static NSString* BHTLocalized(NSString* key, NSString* fallback) {
    NSString* s = [[BHTBundle sharedBundle] localizedStringForKey:key];
    if (s.length && ![s isEqualToString:key]) {
        return s;
    }
    s = [[BHTBundle sharedBundle] localizedTwitterStringForKey:key];
    if (s.length && ![s isEqualToString:key]) {
        return s;
    }
    return fallback;
}

static void CollectAPIError(id obj, long* outCode, NSString** outMessage, int depth) {
    if (!obj || depth > 4 || (!outCode && !outMessage)) {
        return;
    }

    if ([obj isKindOfClass:[NSError class]]) {
        NSError* e = obj;
        CollectAPIError(e.userInfo, outCode, outMessage, depth + 1);
        return;
    }

    if ([obj isKindOfClass:[NSDictionary class]]) {
        NSDictionary* dict = obj;
        for (id key in dict) {
            id value = dict[key];
            NSString* keyStr = [key isKindOfClass:[NSString class]] ? key : [key description];
            NSString* lower = [keyStr lowercaseString];
            if (outCode && *outCode == 0 &&
                ([lower containsString:@"apierrorcode"] || [lower containsString:@"errorcode"])) {
                if ([value respondsToSelector:@selector(integerValue)]) {
                    long v = [value integerValue];
                    if (v != 0) {
                        *outCode = v;
                    }
                }
            }
            if (outMessage && !*outMessage &&
                ([lower containsString:@"apierrormessage"] ||
                 [lower containsString:@"errormessage"] ||
                 [lower isEqualToString:@"message"])) {
                if ([value isKindOfClass:[NSString class]] && ((NSString*)value).length) {
                    *outMessage = value;
                }
            }
        }
        for (id value in [dict allValues]) {
            if ((outCode && *outCode != 0) && (outMessage && *outMessage)) {
                break;
            }
            if ([value isKindOfClass:[NSDictionary class]] ||
                [value isKindOfClass:[NSArray class]] ||
                [value isKindOfClass:[NSError class]]) {
                CollectAPIError(value, outCode, outMessage, depth + 1);
            }
        }
        return;
    }

    if ([obj isKindOfClass:[NSArray class]]) {
        for (id value in (NSArray*)obj) {
            if ((outCode && *outCode != 0) && (outMessage && *outMessage)) {
                break;
            }
            CollectAPIError(value, outCode, outMessage, depth + 1);
        }
    }
}

static long HTTPStatus(id error) {
    if ([error isKindOfClass:[NSError class]]) {
        return (long)((NSError*)error).code;
    }
    return 0;
}

#pragma mark - LocalDevVPN (jkcoxson) helpers

// LocalDevVPN's documented URL interface (jkcoxson/LocalDevVPN,
// LocalDevVPNApp.swift -handleURL:): localdevvpn://enable?scheme=<callback>
// starts the loopback tunnel, then bounces back to the caller's scheme.
// The host app answers to twitter://, so pass that as the callback.
static NSString* const kLocalDevVPNEnableURL = @"localdevvpn://enable?scheme=twitter";
static NSString* const kLocalDevVPNAppURL = @"localdevvpn://";
static NSString* const kLocalDevVPNAppStoreURL =
    @"https://apps.apple.com/us/app/localdevvpn/id6755608044";
static NSString* const kLocalDevVPNRepoURL = @"https://github.com/jkcoxson/LocalDevVPN";
static NSString* const kVPNPreflightSkipKey = @"bht_login_vpn_preflight_skipped";

typedef NS_ENUM(NSInteger, BHTVPNStatus) {
    BHTVPNStatusOff = 0,      // no utun tunnel up
    BHTVPNStatusOther = 1,    // some VPN tunnel up, but not LocalDevVPN's 10.7.x.x
    BHTVPNStatusLocalDev = 2, // LocalDevVPN's default 10.7.0.1/10.7.1.1 pair seen
};

// No VPN entitlement needed: a connected tunnel always shows up as a running
// utun interface. LocalDevVPN defaults to 10.7.1.1/32 (iface) + 10.7.0.1/32
// (peer), so an up utun carrying 10.7.x.x is almost certainly it.
static BHTVPNStatus LocalDevVPNStatus(void) {
    struct ifaddrs* addrs = NULL;
    if (getifaddrs(&addrs) != 0) {
        return BHTVPNStatusOff;
    }

    BOOL anyTunnel = NO;
    BOOL localDev = NO;
    for (struct ifaddrs* cur = addrs; cur; cur = cur->ifa_next) {
        if (!cur->ifa_name || !cur->ifa_addr) {
            continue;
        }
        if (strncmp(cur->ifa_name, "utun", 4) != 0) {
            continue;
        }
        if (!(cur->ifa_flags & IFF_UP) || !(cur->ifa_flags & IFF_RUNNING)) {
            continue;
        }
        if (cur->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        anyTunnel = YES;

        char buf[INET_ADDRSTRLEN] = {0};
        struct sockaddr_in* sin = (struct sockaddr_in*)cur->ifa_addr;
        if (inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf))) {
            if (strncmp(buf, "10.7.", 5) == 0) {
                localDev = YES;
                break;
            }
        }
    }
    freeifaddrs(addrs);

    if (localDev) {
        return BHTVPNStatusLocalDev;
    }
    return anyTunnel ? BHTVPNStatusOther : BHTVPNStatusOff;
}

#pragma mark - ui_metrics injection

// Hooks fetch/XHR/sendBeacon inside the js_inst page and forwards the requested URLs,
// so we can take the anti-bot `result=` token.
static NSString* const kJSInstJS =
    @"(function(){function "
    @"rep(u){try{window.webkit.messageHandlers.bht.postMessage(String(u));}catch(e){}}"
    @"var "
    @"of=window.fetch;if(of){window.fetch=function(){try{rep(arguments[0]&&arguments[0].url?"
    @"arguments[0].url:arguments[0]);}catch(e){}return of.apply(this,arguments);};}"
    @"var "
    @"oo=XMLHttpRequest.prototype.open;XMLHttpRequest.prototype.open=function(m,u){try{rep(u);}"
    @"catch(e){}return oo.apply(this,arguments);};"
    @"if(navigator.sendBeacon){var "
    @"sb=navigator.sendBeacon.bind(navigator);navigator.sendBeacon=function(u,d){try{rep(u);}catch("
    @"e){}return sb(u,d);};}})();";

@interface LegacyLoginViewController () <WKNavigationDelegate, WKScriptMessageHandler>

@property (nonatomic, strong) UITextField* userField;
@property (nonatomic, strong) UITextField* passField;
@property (nonatomic, strong) UIButton* actionButton;
@property (nonatomic, strong) UILabel* infoLabel;
@property (nonatomic, strong) UILabel* vpnStatusLabel;
@property (nonatomic, strong) UIButton* vpnButton;
@property (nonatomic, strong) TFNHUD* hud;

@property (nonatomic, strong) WKWebView* instWebView;
@property (nonatomic, copy) NSString* uiMetrics;
@property (nonatomic, copy) void (^metricsCallback)(NSString*);
@property (nonatomic, assign) BOOL metricsDone;

// Set once the user passes the VPN preflight (or the tunnel is up), so
// explicit retries from error alerts don't re-show the nudge each time.
@property (nonatomic, assign) BOOL vpnPreflightPassed;

@property (nonatomic, assign) BOOL asRootScreen; // YES when installed as the signed-out screen

@end

@implementation LegacyLoginViewController

#pragma mark - Presentation

+ (BOOL)bht_isOurs:(UIViewController*)vc {
    if ([vc isKindOfClass:[LegacyLoginViewController class]]) {
        return YES;
    }

    if ([vc isKindOfClass:[UINavigationController class]]) {
        id root = ((UINavigationController*)vc).viewControllers.firstObject;
        return [root isKindOfClass:[LegacyLoginViewController class]];
    }

    return NO;
}

+ (void)presentLoginFrom:(UIViewController*)presenter {
    if (!presenter) {
        return;
    }

    // Return if the form is already anywhere in the presentation chain
    for (UIViewController* vc = presenter; vc; vc = vc.presentedViewController) {
        if ([self bht_isOurs:vc]) {
            return;
        }
    }

    while (presenter.presentedViewController) {
        presenter = presenter.presentedViewController;
    }

    LegacyLoginViewController* login = [[LegacyLoginViewController alloc] init];
    UINavigationController* nav = [[UINavigationController alloc] initWithRootViewController:login];
    nav.modalPresentationStyle = UIModalPresentationFullScreen;

    [presenter presentViewController:nav animated:YES completion:nil];
}

+ (UINavigationController*)loginRootNavigationController {
    LegacyLoginViewController* login = [[LegacyLoginViewController alloc] init];
    login.asRootScreen = YES;

    return [[UINavigationController alloc] initWithRootViewController:login];
}

#pragma mark - View setup

- (void)viewDidLoad {
    [super viewDidLoad];

    self.view.backgroundColor = [UIColor systemBackgroundColor];
    self.title = [[BHTBundle sharedBundle] localizedStringForKey:@"LOG_IN_TITLE"];

    if (!self.asRootScreen) {
        self.navigationItem.leftBarButtonItem =
            [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemCancel
                                                          target:self
                                                          action:@selector(cancelTapped)];
    }

    self.infoLabel =
        [self label:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_INFO_LABEL"]];

    self.userField = [self field:[[BHTBundle sharedBundle]
                                     localizedStringForKey:@"PHONE_OR_EMAIL_OR_USERNAME_LABEL"]
                          secure:NO];
    self.userField.keyboardType = UIKeyboardTypeEmailAddress;
    // Content types let iOS Password AutoFill offer saved logins.
    self.userField.textContentType = UITextContentTypeUsername;

    self.passField =
        [self field:[[BHTBundle sharedBundle] localizedStringForKey:@"PASSWORD_LABEL"]
             secure:YES];
    self.passField.textContentType = UITextContentTypePassword;

    self.actionButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.actionButton
        setTitle:[[BHTBundle sharedBundle] localizedStringForKey:@"LOG_IN_ACTION_LABEL"]
        forState:UIControlStateNormal];
    self.actionButton.titleLabel.font = [UIFont boldSystemFontOfSize:18];
    self.actionButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.actionButton addTarget:self
                          action:@selector(actionTapped)
                forControlEvents:UIControlEventTouchUpInside];

    self.vpnStatusLabel = [self label:@""];
    self.vpnStatusLabel.font = [UIFont systemFontOfSize:13];

    self.vpnButton = [UIButton buttonWithType:UIButtonTypeSystem];
    [self.vpnButton setTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONNECT_BUTTON",
                                          @"Connect via LocalDevVPN")
                    forState:UIControlStateNormal];
    self.vpnButton.titleLabel.font = [UIFont systemFontOfSize:15];
    self.vpnButton.contentHorizontalAlignment = UIControlContentHorizontalAlignmentLeading;
    self.vpnButton.translatesAutoresizingMaskIntoConstraints = NO;
    [self.vpnButton addTarget:self
                       action:@selector(vpnButtonTapped)
             forControlEvents:UIControlEventTouchUpInside];

    NSArray* fields =
        @[self.infoLabel, self.vpnStatusLabel, self.vpnButton, self.userField, self.passField,
          self.actionButton];
    UIStackView* stack = [[UIStackView alloc] initWithArrangedSubviews:fields];
    stack.axis = UILayoutConstraintAxisVertical;
    stack.spacing = 14;
    stack.translatesAutoresizingMaskIntoConstraints = NO;
    [self.view addSubview:stack];

    [NSLayoutConstraint activateConstraints:@[
        [stack.topAnchor constraintEqualToAnchor:self.view.safeAreaLayoutGuide.topAnchor
                                        constant:24],
        [stack.leadingAnchor constraintEqualToAnchor:self.view.leadingAnchor
                                            constant:32],
        [stack.trailingAnchor constraintEqualToAnchor:self.view.trailingAnchor
                                             constant:-32],
        [self.userField.heightAnchor constraintEqualToConstant:44],
        [self.passField.heightAnchor constraintEqualToConstant:44],
    ]];
}

- (UITextField*)field:(NSString*)placeholder secure:(BOOL)secure {
    UITextField* field = [[UITextField alloc] init];
    field.placeholder = placeholder;
    field.secureTextEntry = secure;
    field.borderStyle = UITextBorderStyleRoundedRect;
    field.autocapitalizationType = UITextAutocapitalizationTypeNone;
    field.autocorrectionType = UITextAutocorrectionTypeNo;
    field.translatesAutoresizingMaskIntoConstraints = NO;

    return field;
}

- (UILabel*)label:(NSString*)text {
    UILabel* label = [[UILabel alloc] init];
    label.numberOfLines = 0;
    label.font = [UIFont systemFontOfSize:14];
    label.textColor = [UIColor secondaryLabelColor];
    label.text = text;
    label.translatesAutoresizingMaskIntoConstraints = NO;

    return label;
}

#pragma mark - Actions

- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [[NSNotificationCenter defaultCenter] addObserver:self
                                             selector:@selector(refreshVPNStatus)
                                                 name:UIApplicationDidBecomeActiveNotification
                                               object:nil];
    [self refreshVPNStatus];
}

- (void)viewWillDisappear:(BOOL)animated {
    [super viewWillDisappear:animated];
    [[NSNotificationCenter defaultCenter] removeObserver:self
                                                    name:UIApplicationDidBecomeActiveNotification
                                                  object:nil];
}

- (void)refreshVPNStatus {
    if (!self.vpnStatusLabel) {
        return;
    }
    switch (LocalDevVPNStatus()) {
        case BHTVPNStatusLocalDev:
            self.vpnStatusLabel.text = BHTLocalized(
                @"LEGACY_LOGIN_VPN_STATUS_CONNECTED",
                @"LocalDevVPN: connected — login will go through the tunnel.");
            self.vpnStatusLabel.textColor = [UIColor systemGreenColor];
            [self.vpnButton setTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_OPEN_BUTTON", @"Open LocalDevVPN")
                            forState:UIControlStateNormal];
            break;
        case BHTVPNStatusOther:
            self.vpnStatusLabel.text = BHTLocalized(@"LEGACY_LOGIN_VPN_STATUS_OTHER",
                                                    @"VPN: connected (not LocalDevVPN).");
            self.vpnStatusLabel.textColor = [UIColor systemGreenColor];
            [self.vpnButton setTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONNECT_BUTTON",
                                                  @"Connect via LocalDevVPN")
                            forState:UIControlStateNormal];
            break;
        case BHTVPNStatusOff:
        default:
            self.vpnStatusLabel.text = BHTLocalized(
                @"LEGACY_LOGIN_VPN_STATUS_OFF",
                @"LocalDevVPN not detected. Connect it before signing in to avoid rate limits.");
            self.vpnStatusLabel.textColor = [UIColor secondaryLabelColor];
            [self.vpnButton setTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONNECT_BUTTON",
                                                  @"Connect via LocalDevVPN")
                            forState:UIControlStateNormal];
            break;
    }
}

// Opens LocalDevVPN (plain app URL when the tunnel is already up, otherwise
// its enable URL, localdevvpn://enable?scheme=twitter, which starts the
// loopback tunnel and bounces back here). No LSApplicationQueriesSchemes
// entry is needed: -openURL: works without one, and the completion handler
// tells us when the app isn't installed.
- (void)openLocalDevVPN {
    BHTVPNStatus status = LocalDevVPNStatus();
    NSURL* url = [NSURL URLWithString:(status == BHTVPNStatusLocalDev ? kLocalDevVPNAppURL
                                                                      : kLocalDevVPNEnableURL)];
    if (!url) {
        return;
    }
    __weak typeof(self) ws = self;
    [[UIApplication sharedApplication] openURL:url
                                       options:@{}
                             completionHandler:^(BOOL success) {
                                 if (!success) {
                                     dispatch_async(dispatch_get_main_queue(), ^{
                                         [ws showLocalDevVPNMissing];
                                     });
                                 }
                             }];
}

- (void)showLocalDevVPNMissing {
    NSString* msg = BHTLocalized(
        @"LEGACY_LOGIN_VPN_MISSING_MESSAGE",
        ([NSString stringWithFormat:@"LocalDevVPN isn't installed, so the tunnel can't be started "
                                    @"from here. Get it free on the App Store (%@) or from %@, "
                                    @"connect it, then return and try logging in again.",
                                    kLocalDevVPNAppStoreURL, kLocalDevVPNRepoURL]));
    [self alert:BHTLocalized(@"LEGACY_LOGIN_VPN_MISSING_TITLE", @"LocalDevVPN not installed")
            msg:msg];
}

- (void)vpnButtonTapped {
    [self refreshVPNStatus];
    [self openLocalDevVPN];
}

- (void)showVPNPreflight {
    NSString* title = BHTLocalized(@"LEGACY_LOGIN_VPN_NEEDED_TITLE", @"VPN not detected");
    NSString* msg = BHTLocalized(
        @"LEGACY_LOGIN_VPN_NEEDED_MESSAGE",
        @"LocalDevVPN doesn't appear to be connected. Twitter rate-limits password logins per "
        @"network (error 243); signing in through the tunnel keeps retries off your direct "
        @"connection. Connect LocalDevVPN first?");
    UIAlertController* sheet =
        [UIAlertController alertControllerWithTitle:title
                                            message:msg
                                     preferredStyle:UIAlertControllerStyleAlert];
    __weak typeof(self) ws = self;
    [sheet addAction:[UIAlertAction
                         actionWithTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONNECT_BUTTON",
                                                      @"Connect via LocalDevVPN")
                                   style:UIAlertActionStyleDefault
                                 handler:^(__unused UIAlertAction* _a) {
                                     [ws openLocalDevVPN];
                                 }]];
    [sheet addAction:[UIAlertAction
                         actionWithTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONTINUE", @"Continue anyway")
                                   style:UIAlertActionStyleDefault
                                 handler:^(__unused UIAlertAction* _a) {
                                     ws.vpnPreflightPassed = YES;
                                     [ws startLogin];
                                 }]];
    [sheet addAction:[UIAlertAction
                         actionWithTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONTINUE_SILENT",
                                                      @"Continue & don't ask again")
                                   style:UIAlertActionStyleDefault
                                 handler:^(__unused UIAlertAction* _a) {
                                     [[NSUserDefaults standardUserDefaults]
                                         setBool:YES
                                          forKey:kVPNPreflightSkipKey];
                                     ws.vpnPreflightPassed = YES;
                                     [ws startLogin];
                                 }]];
    [sheet addAction:[UIAlertAction actionWithTitle:BHTLocalized(@"CANCEL_ACTION_LABEL", @"Cancel")
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)cancelTapped {
    [self dismissViewControllerAnimated:YES completion:nil];
}

- (void)actionTapped {
    [self.view endEditing:YES];
    [self startLogin];
}

- (void)showHUD:(NSString*)text {
    self.hud = [[objc_getClass("TFNHUD") alloc] initWithText:text];
    [self.hud show];
}

#pragma mark - ui_metrics

- (void)generateUIMetrics:(void (^)(NSString*))then {
    self.uiMetrics = nil;
    self.metricsDone = NO;
    self.metricsCallback = then;

    WKWebViewConfiguration* cfg = [[WKWebViewConfiguration alloc] init];
    cfg.websiteDataStore = [WKWebsiteDataStore nonPersistentDataStore];
    [cfg.userContentController addScriptMessageHandler:self name:@"bht"];

    WKUserScript* script =
        [[WKUserScript alloc] initWithSource:kJSInstJS
                               injectionTime:WKUserScriptInjectionTimeAtDocumentStart
                            forMainFrameOnly:NO];
    [cfg.userContentController addUserScript:script];

    self.instWebView = [[WKWebView alloc] initWithFrame:self.view.bounds configuration:cfg];
    self.instWebView.navigationDelegate = self;
    self.instWebView.alpha = 0.02;
    [self.view addSubview:self.instWebView];

    NSURL* url = [NSURL URLWithString:@"https://x.com/i/js_inst?native=true"];
    [self.instWebView loadRequest:[NSURLRequest requestWithURL:url]];

    // Give up after a while so a failed js_inst load can't wedge the login.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(12 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
                       [self finishMetrics];
                   });
}

- (void)finishMetrics {
    if (self.metricsDone) {
        return;
    }
    self.metricsDone = YES;

    [self.instWebView removeFromSuperview];
    self.instWebView = nil;

    void (^cb)(NSString*) = self.metricsCallback;
    self.metricsCallback = nil;

    if (cb) {
        cb(self.uiMetrics);
    }
}

- (void)consumeURL:(NSString*)urlString {
    if (self.uiMetrics || ![urlString containsString:@"result="]) {
        return;
    }

    NSURLComponents* components = [NSURLComponents componentsWithURL:[NSURL URLWithString:urlString]
                                             resolvingAgainstBaseURL:NO];
    for (NSURLQueryItem* item in components.queryItems) {
        if ([item.name isEqualToString:@"result"] && item.value.length) {
            self.uiMetrics = item.value;
            dispatch_async(dispatch_get_main_queue(), ^{
                [self finishMetrics];
            });
            return;
        }
    }
}

- (void)userContentController:(WKUserContentController*)controller
      didReceiveScriptMessage:(WKScriptMessage*)message {
    if ([message.body isKindOfClass:[NSString class]]) {
        [self consumeURL:message.body];
    }
}

- (void)webView:(WKWebView*)webView
    decidePolicyForNavigationAction:(WKNavigationAction*)action
                    decisionHandler:(void (^)(WKNavigationActionPolicy))handler {
    [self consumeURL:action.request.URL.absoluteString];
    handler(WKNavigationActionPolicyAllow);
}

#pragma mark - Step 1: password

- (void)startLogin {
    NSString* user = self.userField.text ?: @"";
    NSString* pass = self.passField.text ?: @"";
    if (user.length == 0 || pass.length == 0) {
        [self alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_MISSING_INPUT_TITLE"]
                msg:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_MISSING_INPUT_MESSAGE"]];
        return;
    }

    // LocalDevVPN preflight: password logins are per-IP rate-limited (api 243)
    // and a loopback tunnel keeps retries off the direct connection. Nudge
    // once per install unless the user opts out below; explicit retries
    // (vpnPreflightPassed) skip it.
    if (!self.vpnPreflightPassed && LocalDevVPNStatus() == BHTVPNStatusOff &&
        ![[NSUserDefaults standardUserDefaults] boolForKey:kVPNPreflightSkipKey]) {
        [self showVPNPreflight];
        return;
    }
    self.vpnPreflightPassed = YES;

    [self showHUD:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_VERIFYING_STATUS"]];

    [self generateUIMetrics:^(NSString* metrics) {
        [self.hud
            setText:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_SIGNING_IN_STATUS"]];

        Class cmdCls = objc_getClass("TFSTwitterAPIXAuthPasswordCommand");
        if (!cmdCls || !Loader() || !Context()) {
            [self.hud hide];
            [self alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_UNAVAILABLE_TITLE"]
                    msg:[[BHTBundle sharedBundle]
                            localizedStringForKey:@"LEGACY_LOGIN_CLASSES_MISSING_MESSAGE"]];
            return;
        }

        __weak typeof(self) ws = self;
        CmdCompletion completion = ^(BOOL ok, id resp, id err) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [ws handlePassword:ok response:resp error:err];
            });
        };

        @try {
            SEL sel = @selector(initWithContext:accountID:authContext:identifier:password:simCountryCode:
                                httpRequestConfiguration:supportOneFactorAuthorization:knownDeviceToken:
                                uiMetrics:authTokenStorage:source:responseModelBuilder:completionBlock:);
            PwInitIMP imp = (PwInitIMP)objc_msgSend;

            id cmd = imp([cmdCls alloc], sel, Context(), GuestAccountID(), nil, user, pass, nil,
                         HTTPConfig(), NO, KnownDeviceToken(), metrics, Storage(), nil,
                         Builder("TFSTwitterXAuthPasswordResponseBuilder"), [completion copy]);
            if (!cmd) {
                [self.hud hide];
                [self
                    alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_UNAVAILABLE_TITLE"]
                      msg:[[BHTBundle sharedBundle]
                              localizedStringForKey:@"LEGACY_LOGIN_BUILD_COMMAND_FAILED_MESSAGE"]];
                return;
            }

            ((void (*)(id, SEL, id))objc_msgSend)(Loader(), @selector(startCommand:), cmd);
        } @catch (NSException* ex) {
            [self.hud hide];
            [self
                alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_CRASH_AVOIDED_TITLE"]
                  msg:ex.reason ?: ex.description];
        }
    }];
}

- (void)handlePassword:(BOOL)ok response:(id)resp error:(id)err {
    [self.hud hide];

    if (!ok) {
        [self alertError:err
                   title:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_FAILED_TITLE"]];
        return;
    }

    id token = Perform0(resp, @selector(token));
    id secret = Perform0(resp, @selector(tokenSecret));
    if (token && secret) {
        id screenName = Perform0(resp, @selector(screenName)) ?: Perform0(resp, @selector(username));
        [self buildAndAddAccountWithToken:token
                                   secret:secret
                               screenName:screenName
                                   userId:UserId(resp, @selector(userId))];
        return;
    }

    if (!Perform0(resp, @selector(loginVerificationRequestId))) {
        [self alert:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_UNEXPECTED_RESPONSE_TITLE"]
                msg:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_NO_TOKEN_NO_CHALLENGE_MESSAGE"]];
        return;
    }

    [self presentChallengeForResponse:resp];
}

#pragma mark - Step 2: 2FA / login-verification (web challenge)

- (void)presentChallengeForResponse:(id)resp {
    id requestID = Perform0(resp, @selector(loginVerificationRequestId));
    id urlString = Perform0(resp, @selector(challengeURLString));

    long long userID = UserId(resp, @selector(loginVerificationUserId));
    if (!userID) {
        userID = UserId(resp, @selector(userId));
    }

    long long loginType = 0;
    long long cause = 0;
    if ([resp respondsToSelector:@selector(loginVerificationRequestType)]) {
        loginType = ((int (*)(id, SEL))objc_msgSend)(resp, @selector(loginVerificationRequestType));
    }
    if ([resp respondsToSelector:@selector(loginVerificationRequestCause)]) {
        cause = ((int (*)(id, SEL))objc_msgSend)(resp, @selector(loginVerificationRequestCause));
    }

    if (!requestID || !urlString) {
        [self alert:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_UNEXPECTED_RESPONSE_TITLE"]
                msg:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_CHALLENGE_MISSING_INFO_MESSAGE"]];
        return;
    }

    BOOL securityKey = NO;
    Class tps = objc_getClass("TPSDeviceFeatureSwitches");
    if (tps && [tps respondsToSelector:@selector(isSecurityKeyAuthEnabled)]) {
        securityKey = ((BOOL (*)(id, SEL))objc_msgSend)(tps, @selector(isSecurityKeyAuthEnabled));
    }

    Class factoryCls = objc_getClass("T1LoginChallengeFactory");
    id host = Perform0(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
    if (!factoryCls || !host) {
        [self alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_UNAVAILABLE_TITLE"]
                msg:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_CHALLENGE_CLASSES_MISSING_MESSAGE"]];
        return;
    }

    @try {
        SEL sel =
            @selector(loginChallengeWithMode:loginType:requestID:user:userID:URLString:loginCause:);
        id (*imp)(id, SEL, long long, long long, id, id, long long, id, long long) =
            (id (*)(id, SEL, long long, long long, id, id, long long, id, long long))objc_msgSend;

        id challenge = imp(factoryCls, sel, securityKey ? 1 : 0, loginType, requestID,
                           self.userField.text ?: @"", userID, urlString, cause);
        if (!challenge) {
            [self alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_UNAVAILABLE_TITLE"]
                    msg:[[BHTBundle sharedBundle]
                            localizedStringForKey:@"LEGACY_LOGIN_BUILD_CHALLENGE_FAILED_MESSAGE"]];
            return;
        }

        void (^added)(id, id) = ^(id challengeVC, id account) {
            RegisterAccount(account);

            void (^switchBlock)(void) = ^{
                SwitchToAccount(account);
            };

            UIViewController* h =
                Perform0(objc_getClass("T1HostViewController"), @selector(sharedHostViewController));
            if (h.presentedViewController) {
                [h dismissViewControllerAnimated:YES completion:switchBlock];
            } else {
                switchBlock();
            }
        };

        if ([challenge respondsToSelector:@selector(setDidAddAccountBlock:)]) {
            ((void (*)(id, SEL, id))objc_msgSend)(challenge, @selector(setDidAddAccountBlock:),
                                                  [added copy]);
        }

        if ([host respondsToSelector:@selector(setLoginChallengeProvider:)]) {
            ((void (*)(id, SEL, id))objc_msgSend)(host, @selector(setLoginChallengeProvider:), challenge);
        }

        void (^present)(void) = ^{
            SEL presentSel = @selector(presentLoginChallengeFromViewController:animated:completion:);
            ((void (*)(id, SEL, id, BOOL, id))objc_msgSend)(challenge, presentSel, host, YES, (id)nil);
        };

        id flow = nil;
        if ([host respondsToSelector:@selector(signedOutOnboardingFlow)]) {
            flow = Perform0(host, @selector(signedOutOnboardingFlow));
        }

        if (flow && [flow respondsToSelector:@selector(completeFlowAnimated:completion:)]) {
            ((void (*)(id, SEL, BOOL, id))objc_msgSend)(flow, @selector(completeFlowAnimated:completion:),
                                                        NO, present);
        } else {
            present();
        }
    } @catch (NSException* ex) {
        [self alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_CRASH_AVOIDED_TITLE"]
                msg:ex.reason ?: ex.description];
    }
}

#pragma mark - Account

- (void)buildAndAddAccountWithToken:(id)token
                             secret:(id)secret
                         screenName:(id)screenName
                             userId:(long long)userId {
    if (!token || !secret) {
        [self alert:[[BHTBundle sharedBundle]
                        localizedStringForKey:@"LEGACY_LOGIN_UNEXPECTED_RESPONSE_TITLE"]
                msg:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_NO_TOKEN_MESSAGE"]];
        return;
    }

    Class accountCls = objc_getClass("TFNTwitterAccount");
    id account = ((id (*)(id, SEL, id, long long))objc_msgSend)(
        [accountCls alloc], @selector(initWithUsername:userID:), screenName, userId);

    if ([account
            respondsToSelector:@selector(updateUserInfoAndCredentialsWithToken:secret:username:)]) {
        ((void (*)(id, SEL, id, id, id))objc_msgSend)(
            account, @selector(updateUserInfoAndCredentialsWithToken:secret:username:), token, secret,
            screenName);
    }

    [self addAndSwitchToAccount:account];
}

- (void)addAndSwitchToAccount:(id)account {
    if (!account) {
        [self
            alert:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_FAILED_TITLE"]
              msg:[[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_NO_ACCOUNT_MESSAGE"]];
        return;
    }

    RegisterAccount(account);

    void (^switchBlock)(void) = ^{
        SwitchToAccount(account);
    };

    UIViewController* popup = self.presentingViewController;
    if (!popup) {
        switchBlock();
        return;
    }

    UIViewController* dismisser = popup.presentingViewController ?: popup;
    [dismisser dismissViewControllerAnimated:YES completion:switchBlock];
}

#pragma mark - Alerts

- (NSString*)errorText:(id)error {
    if ([error isKindOfClass:[NSError class]]) {
        NSError* e = error;
        long apiCode = 0;
        NSString* apiMessage = nil;
        CollectAPIError(e, &apiCode, &apiMessage, 0);

        // Prefer the server's own message ("Sorry, that page does not exist.")
        // over a raw userInfo dump.
        if (apiMessage.length || apiCode != 0) {
            if (apiMessage.length && apiCode != 0) {
                return [NSString stringWithFormat:@"%@ (code %ld, HTTP %ld)", apiMessage,
                                                  apiCode, (long)e.code];
            } else if (apiMessage.length) {
                return [NSString stringWithFormat:@"%@ (HTTP %ld)", apiMessage, (long)e.code];
            } else {
                return [NSString stringWithFormat:@"Twitter error %ld (HTTP %ld)", apiCode,
                                                  (long)e.code];
            }
        }

        NSString* desc = e.localizedDescription;
        if (desc.length && ![desc isEqualToString:e.domain]) {
            return [NSString stringWithFormat:@"%@ (%@ %ld)", desc, e.domain, (long)e.code];
        }
        return [NSString stringWithFormat:@"%@ (%ld)", e.domain, (long)e.code];
    }

    return error ? [error description]
                 : [[BHTBundle sharedBundle] localizedStringForKey:@"LEGACY_LOGIN_UNKNOWN_ERROR"];
}

- (void)alertError:(id)err title:(NSString*)title {
    NSString* details = [self errorText:err];

    // When no tunnel is up, point at LocalDevVPN so retries happen through it
    // instead of burning the direct connection (per-IP error 243).
    NSString* vpnHint = nil;
    if (LocalDevVPNStatus() == BHTVPNStatusOff) {
        vpnHint = BHTLocalized(
            @"LEGACY_LOGIN_VPN_HINT",
            @"Tip: connect LocalDevVPN, then retry — the tunnel keeps login attempts off your "
            @"direct connection.");
    }

    if (IsRateLimit(err)) {
        NSString* msg =
            [NSString stringWithFormat:[[BHTBundle sharedBundle]
                                           localizedStringForKey:@"LEGACY_LOGIN_RATE_LIMITED_MESSAGE"],
                                       details];
        if (vpnHint) {
            msg = [msg stringByAppendingFormat:@"\n\n%@", vpnHint];
        }
        [self alertLoginError:[[BHTBundle sharedBundle]
                                  localizedStringForKey:@"LEGACY_LOGIN_RATE_LIMITED_TITLE"]
                          msg:msg];
        return;
    }

    long apiCode = 0;
    NSString* apiMessage = nil;
    CollectAPIError(err, &apiCode, &apiMessage, 0);
    long http = HTTPStatus(err);

    // 404 + api 34 ("Sorry, that page does not exist."): the xauth_password
    // endpoint this form posts to is gone/blocked for this app build
    // (commonly attestation-gated server-side). A raw
    // "com.twitter.TFSTwitterAPICommand (404) {...}" dump leaves users
    // stuck, so explain and suggest next steps instead.
    if (http == 404 || apiCode == 34) {
        NSString* serverMsg = apiMessage.length ? apiMessage : details;
        NSString* format = BHTLocalized(
            @"LEGACY_LOGIN_ENDPOINT_GONE_MESSAGE",
            @"Twitter refused the password-login request (%@).\n\nThis usually means this "
            @"version of the app can no longer reach Twitter's password-login endpoint "
            @"(retired or gated behind app attestation), not that your username/password is "
            @"wrong.\n\nTry: update NeoFreeBird + the app to a matching supported pair, log "
            @"in once in the official App Store app, then return here — or connect LocalDevVPN "
            @"and retry. Repeated retries can rate-limit the account.");
        NSString* msg = [NSString stringWithFormat:format, serverMsg];
        if (vpnHint) {
            msg = [msg stringByAppendingFormat:@"\n\n%@", vpnHint];
        }
        [self alertLoginError:title msg:msg];
        return;
    }

    // Wrong credentials / bad token (api 32/99/215 etc.): keep the server text
    // but don't bury it in a raw NSError dump.
    if (apiCode == 32 || apiCode == 99 || apiCode == 215 || http == 401 || http == 403) {
        NSString* format = BHTLocalized(@"LEGACY_LOGIN_SERVER_REJECTED_MESSAGE",
                                        @"Twitter rejected the login (%@).\n\nDouble-check the "
                                        @"username and password (usernames are case-insensitive, "
                                        @"passwords are not). If the account uses Google/Apple "
                                        @"sign-in, add a password to it first.");
        [self alertLoginError:title msg:[NSString stringWithFormat:format, details]];
        return;
    }

    [self alertLoginError:title msg:details];
}

// Login failures get Retry + VPN actions; everything else keeps the plain OK
// alert below. Retrying re-runs the full flow (fresh ui_metrics + command),
// and the VPN action jumps straight to LocalDevVPN's enable URL.
- (void)alertLoginError:(NSString*)title msg:(NSString*)message {
    UIAlertController* alert =
        [UIAlertController alertControllerWithTitle:title
                                            message:message
                                     preferredStyle:UIAlertControllerStyleAlert];
    __weak typeof(self) ws = self;
    [alert addAction:[UIAlertAction actionWithTitle:BHTLocalized(@"LEGACY_LOGIN_RETRY_ACTION",
                                                                 @"Retry login")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction* _a) {
                                                // Explicit retry: don't re-show the preflight.
                                                ws.vpnPreflightPassed = YES;
                                                [ws startLogin];
                                            }]];
    [alert addAction:[UIAlertAction actionWithTitle:BHTLocalized(@"LEGACY_LOGIN_VPN_CONNECT_BUTTON",
                                                                 @"Connect via LocalDevVPN")
                                              style:UIAlertActionStyleDefault
                                            handler:^(__unused UIAlertAction* _a) {
                                                [ws openLocalDevVPN];
                                            }]];
    [alert addAction:[UIAlertAction actionWithTitle:BHTLocalized(@"OK_ACTION_LABEL", @"OK")
                                              style:UIAlertActionStyleCancel
                                            handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)alert:(NSString*)title msg:(NSString*)message {
    UIAlertController* alert =
        [UIAlertController alertControllerWithTitle:title
                                             message:message
                                      preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:BHTLocalized(@"OK_ACTION_LABEL", @"OK")
                                             style:UIAlertActionStyleDefault
                                           handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

@end
