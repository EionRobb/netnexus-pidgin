//
//  NetnexusService.m
//  okcupid-adium
//
//  Created by MyMacSpace on 19/09/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import "NetnexusService.h"
#import "NetnexusAccount.h"
#import "NetnexusAccountViewController.h"

@implementation NetnexusService

- (Class)accountClass{
	return [NetnexusAccount class];
}

- (AIAccountViewController *)accountViewController {
	return [NetnexusAccountViewController accountViewController];
}

- (BOOL)supportsProxySettings{
	return NO;
}

- (BOOL)supportsPassword
{
	return YES;
}

- (BOOL)requiresPassword
{
	return YES;
}

- (NSString *)UIDPlaceholder
{
	return @"Netnexus";
}

//Service Description
- (NSString *)serviceCodeUniqueID{
	return @"prpl-bigbrownchunx-netnexus";
}
- (NSString *)serviceID{
	return @"Netnexus";
}
- (NSString *)serviceClass{
	return @"Netnexus";
}
- (NSString *)shortDescription{
	return @"Netnexus";
}
- (NSString *)longDescription{
	return @"Netnexus";
}

- (BOOL)isSocialNetworkingService
{
	return NO;
}

- (NSCharacterSet *)allowedCharacters{
	return [[NSCharacterSet illegalCharacterSet] invertedSet];
}
- (NSCharacterSet *)ignoredCharacters{
	return [NSCharacterSet characterSetWithCharactersInString:@""];
}
- (BOOL)caseSensitive{
	return NO;
}
- (AIServiceImportance)serviceImportance{
	return AIServiceSecondary;
}
- (NSImage *)defaultServiceIconOfType:(AIServiceIconType)iconType
{
	NSImage *image;
	NSString *imagename;
	NSSize imagesize;
	
	if (iconType == AIServiceIconLarge)
	{
		imagename = @"netnexus";
		imagesize = NSMakeSize(48,48);
	} else {
		imagename = @"netnexus-small";
		imagesize = NSMakeSize(16,16);
	}
	
	image = [NSImage imageNamed:(imagename)
					   forClass:[self class] loadLazily:YES];
	[image setSize:imagesize];
	return image;
}
@end
