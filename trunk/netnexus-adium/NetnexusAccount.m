//
//  NetnexusAccount.m
//  okcupid-adium
//
//  Created by MyMacSpace on 19/09/09.
//  Copyright 2009 __MyCompanyName__. All rights reserved.
//

#import <Adium/AIHTMLDecoder.h>
#import "NetnexusAccount.h"


@implementation NetnexusAccount

- (const char*)protocolPlugin
{
	return "prpl-bigbrownchunx-netnexus";
}

- (BOOL)connectivityBasedOnNetworkReachability
{
	return YES;
}

- (NSString *)host
{
	return @"ugp.netnexus.com";
}

- (int)port
{
	return 9867;
}

- (NSString *)encodedAttributedString:(NSAttributedString *)inAttributedString forListObject:(AIListObject *)inListObject
{
	NSString *temp = [AIHTMLDecoder encodeHTML:inAttributedString
									   headers:YES
									  fontTags:NO
							includingColorTags:NO
								 closeFontTags:NO
									 styleTags:NO
					closeStyleTagsOnFontChange:NO
								encodeNonASCII:NO
								  encodeSpaces:NO
									imagesPath:nil
							 attachmentsAsText:YES
					 onlyIncludeOutgoingImages:NO
								simpleTagsOnly:YES
								bodyBackground:NO
						   allowJavascriptURLs:NO];
	return temp;
}


- (BOOL)canSendOfflineMessageToContact:(AIListContact *)inContact
{
	//shortcut parent method
	return NO;
}

@end
