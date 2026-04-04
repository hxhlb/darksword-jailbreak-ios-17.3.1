/*
 * main.m — DarkSword Standalone Jailbreak App
 * Minimal UIKit app entry point.
 */

#import <UIKit/UIKit.h>
#include <signal.h>
#include <unistd.h>

@interface DSAppDelegate : UIResponder <UIApplicationDelegate>
@property (nonatomic, strong) UIWindow *window;
@end

@interface DSViewController : UIViewController
@property (nonatomic, strong) UITextView *logView;
@property (nonatomic, strong) UIButton *jailbreakButton;
@property (nonatomic, strong) UILabel *statusLabel;
@end

/* from darksword_exploit.m */
extern int jailbreak_full(void);
extern void exploit_set_ui_log_callback(void (*callback)(const char *));
extern void ds_set_log_callback(void (*callback)(const char *));
/* from filelog.h */
extern void filelog_init(void);
extern void filelog_write(const char *fmt, ...);
extern void filelog_close(void);
extern const char *filelog_get_path(void);

/* === Global reference to VC for log callback === */
static __weak DSViewController *g_vc = nil;

static void ds_signal_handler(int sig) {
    /* Only async-signal-safe functions here (no filelog_write/filelog_close).
       write(2) to stderr is safe per POSIX. */
    static const char prefix[] = "[fatal] signal ";
    write(STDERR_FILENO, prefix, sizeof(prefix) - 1);
    if (sig >= 10) { char t = '0' + (sig / 10); write(STDERR_FILENO, &t, 1); }
    char d = '0' + (sig % 10);
    write(STDERR_FILENO, &d, 1);
    write(STDERR_FILENO, "\n", 1);
    signal(sig, SIG_DFL);
    raise(sig);
}

static void ds_uncaught_exception_handler(NSException *ex) {
    filelog_write("[fatal] uncaught exception: %s", ex.name.UTF8String ?: "<null>");
    filelog_write("[fatal] reason: %s", ex.reason.UTF8String ?: "<null>");
    filelog_close();
}

static void ds_install_panic_resilient_logging(void) {
    filelog_init();
    filelog_write("=== app launch ===");
    filelog_write("logger preinitialized before exploit start");
    NSSetUncaughtExceptionHandler(ds_uncaught_exception_handler);
    signal(SIGTERM, ds_signal_handler);
    signal(SIGABRT, ds_signal_handler);
    signal(SIGSEGV, ds_signal_handler);
    signal(SIGBUS,  ds_signal_handler);
    signal(SIGILL,  ds_signal_handler);
    signal(SIGTRAP, ds_signal_handler);
}

static void ui_log_callback(const char *msg) {
    NSString *line = [NSString stringWithFormat:@"%s\n", msg];
    dispatch_async(dispatch_get_main_queue(), ^{
        DSViewController *vc = g_vc; /* strong ref from weak */
        UITextView *tv = vc.logView;
        if (tv) {
            /* O(1) append via textStorage instead of O(n) stringByAppendingString */
            NSDictionary *attrs = @{
                NSFontAttributeName: tv.font ?: [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular],
                NSForegroundColorAttributeName: tv.textColor ?: [UIColor greenColor]
            };
            NSAttributedString *attrLine = [[NSAttributedString alloc] initWithString:line attributes:attrs];
            [tv.textStorage appendAttributedString:attrLine];
            /* Auto-scroll to bottom */
            if (tv.text.length > 0) {
                NSRange range = NSMakeRange(tv.text.length - 1, 1);
                [tv scrollRangeToVisible:range];
            }
        }
    });
}

#pragma mark - ViewController

@implementation DSViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    g_vc = self;
    
    self.view.backgroundColor = [UIColor blackColor];
    
    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;
    CGFloat pad = 20;
    CGFloat topSafe = 50; /* approximate safe area top */
    
    /* Title label */
    UILabel *title = [[UILabel alloc] initWithFrame:CGRectMake(pad, topSafe, w - pad*2, 40)];
    title.text = @"⚔️ DarkSword Jailbreak";
    title.textColor = [UIColor whiteColor];
    title.font = [UIFont boldSystemFontOfSize:24];
    title.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:title];
    
    /* Status label */
    self.statusLabel = [[UILabel alloc] initWithFrame:CGRectMake(pad, topSafe + 45, w - pad*2, 25)];
    self.statusLabel.text = @"iPad8,9 (A12Z) — Auto mode: baseline → safe → full";
    self.statusLabel.textColor = [UIColor lightGrayColor];
    self.statusLabel.font = [UIFont systemFontOfSize:14];
    self.statusLabel.textAlignment = NSTextAlignmentCenter;
    [self.view addSubview:self.statusLabel];
    
    /* Jailbreak button */
    self.jailbreakButton = [UIButton buttonWithType:UIButtonTypeSystem];
    self.jailbreakButton.frame = CGRectMake(pad, topSafe + 80, w - pad*2, 50);
    [self.jailbreakButton setTitle:@"Auto Jailbreak" forState:UIControlStateNormal];
    self.jailbreakButton.titleLabel.font = [UIFont boldSystemFontOfSize:20];
    [self.jailbreakButton setTitleColor:[UIColor whiteColor] forState:UIControlStateNormal];
    self.jailbreakButton.backgroundColor = [UIColor colorWithRed:0.2 green:0.5 blue:1.0 alpha:1.0];
    self.jailbreakButton.layer.cornerRadius = 12;
    self.jailbreakButton.clipsToBounds = YES;
    [self.jailbreakButton addTarget:self action:@selector(onJailbreak:) forControlEvents:UIControlEventTouchUpInside];
    [self.view addSubview:self.jailbreakButton];
    
    /* Log text view */
    CGFloat logY = topSafe + 145;
    self.logView = [[UITextView alloc] initWithFrame:CGRectMake(pad, logY, w - pad*2, h - logY - pad)];
    self.logView.backgroundColor = [UIColor colorWithWhite:0.1 alpha:1.0];
    self.logView.textColor = [UIColor greenColor];
    self.logView.font = [UIFont fontWithName:@"Menlo" size:11];
    if (!self.logView.font) {
        self.logView.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    }
    self.logView.editable = NO;
    self.logView.layer.cornerRadius = 8;
    self.logView.text = @"DarkSword v1.0 — Ready (auto profiles enabled)\n";
    self.logView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
    [self.view addSubview:self.logView];
    
    /* Show device info */
    NSString *model = [[UIDevice currentDevice] model];
    NSString *sysVer = [[UIDevice currentDevice] systemVersion];
    NSString *sysName = [[UIDevice currentDevice] systemName];
    self.logView.text = [self.logView.text stringByAppendingFormat:
                         @"Device: %@ (%@ %@)\n\n", model, sysName, sysVer];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    CGFloat w = self.view.bounds.size.width;
    CGFloat h = self.view.bounds.size.height;
    CGFloat pad = 20;
    CGFloat topSafe = self.view.safeAreaInsets.top + 10;
    
    /* Reposition for rotation / safe areas */
    CGFloat logY = topSafe + 145;
    self.logView.frame = CGRectMake(pad, logY, w - pad*2, h - logY - self.view.safeAreaInsets.bottom - pad);
}

- (void)onJailbreak:(UIButton *)sender {
    sender.enabled = NO;
    [sender setTitle:@"Running..." forState:UIControlStateNormal];
    sender.backgroundColor = [UIColor darkGrayColor];
    self.statusLabel.text = @"Auto exploit running — DO NOT close this app!";
    self.statusLabel.textColor = [UIColor yellowColor];
    
    self.logView.text = [self.logView.text stringByAppendingString:@"=== Starting auto jailbreak (baseline → safe → full) ===\n\n"];
    
    /* Request extended background execution — prevents iOS from killing us
       if the user accidentally backgrounds the app during kernel exploitation */
    __block UIBackgroundTaskIdentifier bgTask = [[UIApplication sharedApplication]
        beginBackgroundTaskWithName:@"DarkSwordJailbreak"
        expirationHandler:^{
            filelog_write("[warn] iOS background time expiring!");
            [[UIApplication sharedApplication] endBackgroundTask:bgTask];
            bgTask = UIBackgroundTaskInvalid;
        }];
    
    /* Run on background thread to keep UI responsive */
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_HIGH, 0), ^{
        /* Route all exploit/module logs into the on-screen log view */
        exploit_set_ui_log_callback(ui_log_callback);
        ds_set_log_callback(ui_log_callback);
        
        int result = jailbreak_full();
        
        /* End background task — exploit finished */
        if (bgTask != UIBackgroundTaskInvalid) {
            [[UIApplication sharedApplication] endBackgroundTask:bgTask];
            bgTask = UIBackgroundTaskInvalid;
        }
        
        dispatch_async(dispatch_get_main_queue(), ^{
            if (result == 0) {
                self.statusLabel.text = @"✅ Jailbreak complete!";
                self.statusLabel.textColor = [UIColor greenColor];
                [sender setTitle:@"Done ✓" forState:UIControlStateNormal];
                sender.backgroundColor = [UIColor colorWithRed:0.1 green:0.7 blue:0.2 alpha:1.0];
            } else {
                self.statusLabel.text = [NSString stringWithFormat:@"⚠️ Completed with %d issue(s)", result];
                self.statusLabel.textColor = [UIColor orangeColor];
                [sender setTitle:@"Retry" forState:UIControlStateNormal];
                sender.backgroundColor = [UIColor colorWithRed:0.8 green:0.4 blue:0.0 alpha:1.0];
                sender.enabled = YES;
            }
            
            /* Show log location */
            const char *logpath = filelog_get_path();
            if (logpath) {
                self.logView.text = [self.logView.text stringByAppendingFormat:
                                     @"\n📋 Log saved to: %s\n", logpath];
            }
        });
    });
}

- (UIStatusBarStyle)preferredStatusBarStyle {
    return UIStatusBarStyleLightContent;
}

@end

#pragma mark - AppDelegate

@implementation DSAppDelegate

- (BOOL)application:(UIApplication *)application didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    /* NOTE: ds_install_panic_resilient_logging() already called in main() */
    filelog_write("UIApplication didFinishLaunching");

    self.window = [[UIWindow alloc] initWithFrame:[[UIScreen mainScreen] bounds]];
    DSViewController *vc = [[DSViewController alloc] init];
    self.window.rootViewController = vc;
    [self.window makeKeyAndVisible];
    return YES;
}

- (void)applicationWillResignActive:(UIApplication *)application {
    (void)application;
    filelog_write("UIApplication will resign active");
}

- (void)applicationDidEnterBackground:(UIApplication *)application {
    (void)application;
    filelog_write("UIApplication did enter background");
}

- (void)applicationWillTerminate:(UIApplication *)application {
    (void)application;
    filelog_write("UIApplication will terminate");
    exploit_set_ui_log_callback(NULL);
    ds_set_log_callback(NULL);
    filelog_close();
}

@end

#pragma mark - main

int main(int argc, char *argv[]) {
    @autoreleasepool {
        ds_install_panic_resilient_logging();
        filelog_write("main() entered");
        return UIApplicationMain(argc, argv, nil, NSStringFromClass([DSAppDelegate class]));
    }
}
