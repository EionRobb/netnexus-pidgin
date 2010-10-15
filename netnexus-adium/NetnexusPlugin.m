
#import "NetnexusPlugin.h"
#import "NetnexusService.h"

@implementation NetnexusPlugin

- (void)installPlugin
{
	printf("Starting libpurple netnexus plugin\n");
    purple_init_netnexus_plugin();
	printf("Starting Adium netnexus plugin\n");
	service = [[NetnexusService alloc] init];
	printf("Done loading\n");
}

- (void)uninstallPlugin
{
	[service release]; service = nil;
}

@end
