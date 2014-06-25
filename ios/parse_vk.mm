/* vim: set ai noet ts=4 sw=4 tw=115: */
//
// Copyright (c) 2014 Nikolay Zapolnov (zapolnov@gmail.com).
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
#import "parse_vk.h"
#import <yip-imports/ios/NZVKAuthDelegate.h>
#import <yip-imports/ios/NSNotificationCenter+ExtraMethods.h>
#import <yip-imports/ios/image.h>
#import <yip-imports/ios/crypto.h>

#define AUTH_SALT @"PfRQt^6zfQtt%"

@interface Listener : NSObject
{
	void (^ callback)(BOOL success, PFUser * user);
}
@end

@implementation Listener

-(id)initWithCallback:(void(^)(BOOL, PFUser *))cb
{
	self = [super init];
	if (self)
	{
		callback = cb;
		[NSNotificationCenter addObserver:self selector:@selector(onSuccess) name:NZVKontakteReceivedToken];
		[NSNotificationCenter addObserver:self selector:@selector(onFailure) name:NZVKontakteAccessDenied];
	}
	return self;
}

-(void)dealloc
{
	[NSNotificationCenter removeObserver:self];
	[super dealloc];
}

-(void)onSuccess
{
	@try
	{
		if (callback)
		{
			void (^ cb)(BOOL, PFUser *) = callback;

			[PFUser logOut];

			VKRequest * request = [[VKApi users] get:@{ @"fields": @"sex,bdate,photo_max_orig" }];
			request.useSystemLanguage = YES;
			[request executeWithResultBlock:^(VKResponse * response) {
				VKUsersArray * users = response.parsedModel;
				if (users.count == 0)
				{
					[PFUser logOut];
					cb(NO, nil);
					return;
				}

				VKUser * vkUser = [users objectAtIndex:0];
				PFQuery * query = [PFUser query];
				[query whereKey:@"vkID" equalTo:vkUser.id];
				[query getFirstObjectInBackgroundWithBlock:^(PFObject * object, NSError * error) {
					NSString * firstName = vkUser.first_name;
					NSString * lastName = vkUser.last_name;

					NSString * name;
					if (lastName.length == 0)
						name = firstName;
					else if (firstName.length == 0)
						name = lastName;
					else
						name = [NSString stringWithFormat:@"%@ %@", firstName, lastName];

					if (object)
					{
						PFUser * user = (PFUser *)object;
						NSString * login = user.username;
						NSString * pwd = iosCalcMd5ForString([NSString stringWithFormat:@"%@%@", login, AUTH_SALT]);
						[PFUser logInWithUsernameInBackground:login password:pwd
							block:^(PFUser * user, NSError * error)
						{
							if (!user || error)
							{
								[PFUser logOut];
								cb(NO, nil);
								return;
							}

							@try
							{
								user[@"displayName"] = name;
								user[@"displayNameLower"] = [name lowercaseString];
								user[@"sex"] = vkUser.sex;
								user[@"birthDate"] = vkUser.bdate;
								user[@"vkID"] = vkUser.id;
								user[@"vkAvatarURL"] = vkUser.photo_max_orig;
							}
							@catch (id e)
							{
								NSLog(@"Unable to store VK authentication data in PFUser: %@", e);
								[PFUser logOut];
								cb(NO, nil);
								return;
							}

							[user saveInBackgroundWithBlock:^(BOOL succeeded, NSError * error) {
								if (!succeeded || error)
								{
									[PFUser logOut];
									cb(NO, nil);
									return;
								}

								cb(YES, user);
							}];
						}];
					}
					else
					{
						PFUser * user = [PFUser user];

						@try
						{
							user.username = [NSString stringWithFormat:@"<vk-%@>", vkUser.id];
							user.password =
								iosCalcMd5ForString([NSString stringWithFormat:@"%@%@", user.username, AUTH_SALT]);
							user.email = [NSString stringWithFormat:@"vk-%@@vk.com", vkUser.id];
							user[@"displayName"] = name;
							user[@"displayNameLower"] = [name lowercaseString];
							user[@"sex"] = vkUser.sex;
							user[@"birthDate"] = vkUser.bdate;
							user[@"vkID"] = vkUser.id;
							user[@"vkAvatarURL"] = vkUser.photo_max_orig;
						}
						@catch (id e)
						{
							NSLog(@"Unable to store VK authentication data in PFUser: %@", e);
							[PFUser logOut];
							cb(NO, nil);
							return;
						}

						[user signUpInBackgroundWithBlock:^(BOOL succeeded, NSError * error) {
							if (succeeded && !error)
							{
								PFUser * user = [PFUser currentUser];
								if (user)
								{
									cb(YES, user);
									return;
								}
							}

							[PFUser logOut];
							cb(NO, nil);
						}];
					}
				}];
			} errorBlock:^(NSError * error) {
				cb(NO, nil);
			}];
		}
	}
	@finally
	{
		callback = nil;
		[self release];
	}
}

-(void)onFailure
{
	@try
	{
		[PFUser logOut];

		if (callback)
			callback(NO, nil);
	}
	@finally
	{
		callback = nil;
		[self release];
	}
}

@end

void parseVKAuth(void (^ callback)(BOOL success, PFUser * user))
{
	Listener * listener = [[Listener alloc] initWithCallback:callback];

	if ([VKSdk wakeUpSession])
	{
		[listener onSuccess];
		return;
	}

	[VKSdk authorize:@[
		VK_PER_STATUS,
		VK_PER_STATS,
		VK_PER_FRIENDS,
		VK_PER_DOCS,
		VK_PER_NOTES,
		VK_PER_WALL,
		VK_PER_PHOTOS,
		VK_PER_AUDIO,
		VK_PER_VIDEO,
		VK_PER_NOHTTPS,
		VK_PER_OFFLINE
	]];
}

BOOL parseIsUserVKLinked(PFUser * user)
{
	NSString * id = user[@"vkID"];
	return (id.length != 0);
}

void parseGetAvatarForVKUser(PFUser * user, void (^ callback)(UIImage * image))
{
	NSString * url = user[@"vkAvatarURL"];

	if (url.length == 0)
	{
		if (callback)
			callback(nil);
		return;
	}

	iosAsyncDownloadImage(url, callback);
}
