//
//  SecureUDID.m
//  SecureUDID
//
//  Created by Crashlytics Team on 3/22/12.
//  Copyright (c) 2012 Crashlytics, Inc. All rights reserved.
//  http://www.crashlytics.com
//  info@crashlytics.com
//

/*
 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
 of the Software, and to permit persons to whom the Software is furnished to do
 so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 SOFTWARE.
 */

#import "SecureUDID.h"
#import <UIKit/UIKit.h>
#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonKeyDerivation.h>
#import <CommonCrypto/CommonDigest.h>

#define SECURE_UDID_MAX_PASTEBOARD_ENTRIES (100)

NSString *const SUTypeDataDictionary  = @"public.secureudid";
NSString *const SUTimeStampKey        = @"SUTimeStampKey";
NSString *const SUOwnerKey            = @"SUOwnerKey";
NSString *const SUPastboardFileFormat = @"org.secureudid-%d";

NSData * cryptorToData(CCOperation operation, NSData *value, NSData *key);
NSString * cryptorToString(CCOperation operation, NSData *value, NSData *key);
NSString * pasteboardNameForNumber(NSInteger number);
UIPasteboard * pasteboardForEncryptedDomain(NSData *encryptedDomain);

@implementation SecureUDID

+ (NSString *)UDIDForDomain:(NSString *)domain salt:(NSString *)salt {
	NSData *domainAndSalt = [[NSString stringWithFormat:@"%@%@", domain, salt] dataUsingEncoding:NSUTF8StringEncoding];

	uint8_t digest[kCCKeySizeAES128] = {0};
	CC_SHA1(domainAndSalt.bytes, domainAndSalt.length, digest);

	NSData *key = [NSData dataWithBytes:digest length:kCCKeySizeAES128];

	NSData *encryptedDomain = cryptorToData(kCCEncrypt, [domain dataUsingEncoding:NSUTF8StringEncoding], key);

	UIPasteboard *pasteboard = pasteboardForEncryptedDomain(encryptedDomain);

	NSMutableDictionary *secureUDIDDictionary = nil;

	id pasteboardData = [pasteboard dataForPasteboardType:SUTypeDataDictionary];

	if (pasteboardData) {
        pasteboardData = [NSKeyedUnarchiver unarchiveObjectWithData:pasteboardData];
		secureUDIDDictionary = [NSMutableDictionary dictionaryWithDictionary:pasteboardData];
	} else {
		secureUDIDDictionary = [NSMutableDictionary dictionaryWithCapacity:1];
	}

	NSData *valueFromPastboard = [secureUDIDDictionary objectForKey:encryptedDomain];

	if (valueFromPastboard) {
		return cryptorToString(kCCDecrypt, valueFromPastboard, key);
	}

	CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
	CFStringRef uuidStr = CFUUIDCreateString(kCFAllocatorDefault, uuid);
	CFRelease(uuid);

	NSData *data = cryptorToData(kCCEncrypt, [(NSString *)uuidStr dataUsingEncoding:NSUTF8StringEncoding], key);

	[secureUDIDDictionary setObject:data            forKey:encryptedDomain];
	[secureUDIDDictionary setObject:[NSDate date]   forKey:SUTimeStampKey];
	[secureUDIDDictionary setObject:encryptedDomain forKey:SUOwnerKey];

	[pasteboard setData:[NSKeyedArchiver archivedDataWithRootObject:secureUDIDDictionary] forPasteboardType:SUTypeDataDictionary];

	return [(NSString *)uuidStr autorelease];
}

/*
 Applies the operation (encrypt or decrypt) to the NSData value with the provided NSData key returns the vaule as NSData.
 */
NSData * cryptorToData(CCOperation operation, NSData *value, NSData *key) {
    NSMutableData *output = [NSMutableData dataWithLength:value.length + kCCBlockSizeAES128];

    size_t numBytes = 0;
    CCCryptorStatus cryptStatus = CCCrypt(operation,
										  kCCAlgorithmAES128,
										  kCCOptionPKCS7Padding,
                                          [key bytes],
										  kCCKeySizeAES128,
                                          NULL,
                                          value.bytes,
										  value.length,
                                          output.mutableBytes,
										  output.length,
                                          &numBytes);

    if (cryptStatus == kCCSuccess) {
		return [[[NSData alloc] initWithBytes:output.bytes length:numBytes] autorelease];
	}

	return nil;
}

/*
 Applies the operation (encrypt or decrypt) to the NSData value with the provided NSData key returns the vaule as an NSString.
 */
NSString * cryptorToString(CCOperation operation, NSData *value, NSData *key) {
	return [[[NSString alloc] initWithData:cryptorToData(operation, value, key) encoding:NSUTF8StringEncoding] autorelease];
}

/*
 Returns an NSString formatted with the supplied number.
 */
NSString * pasteboardNameForNumber(NSInteger number) {
    return [NSString stringWithFormat:SUPastboardFileFormat, number];
}

/*
 Returns a pasteboard for the encrypted domain. If a pasteboard for the domain is not found a new one is created.
 */
UIPasteboard * pasteboardForEncryptedDomain(NSData *encryptedDomain) {
    UIPasteboard*        usablePasteboard;
    NSInteger            lowestUnusedIndex;
    NSInteger            ownerIndex;
    NSDate*              mostRecentDate;
    NSMutableDictionary* mostRecentDictionary;

    usablePasteboard     = nil;
    lowestUnusedIndex    = INTMAX_MAX;
    mostRecentDate       = [NSDate distantPast];
    mostRecentDictionary = nil;
    ownerIndex           = -1;

    // first, check for matching pasteboards
    for (NSInteger i = 0; i < SECURE_UDID_MAX_PASTEBOARD_ENTRIES; ++i) {
        UIPasteboard* pasteboard;
        NSDate*       modifiedDate;
        NSDictionary* dictionary;
        NSData*       pasteboardData;

        pasteboard = [UIPasteboard pasteboardWithName:pasteboardNameForNumber(i) create:NO];
        if (!pasteboard) {
            if (lowestUnusedIndex == -1) {
                lowestUnusedIndex = i;
            }

            continue;
        }

        // ok, found a pasteboard, check for our value
        pasteboardData = [pasteboard valueForPasteboardType:SUTypeDataDictionary];
        if (!pasteboardData) {
            // corrupted slot
            if (lowestUnusedIndex == -1) {
                lowestUnusedIndex = i;
            }

            continue;
        }

        dictionary   = [NSKeyedUnarchiver unarchiveObjectWithData:pasteboardData];
        modifiedDate = [dictionary valueForKey:SUTimeStampKey];

        if ([modifiedDate compare:mostRecentDate] == NSOrderedDescending) {
            mostRecentDate       = modifiedDate;
            mostRecentDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionary];
            usablePasteboard     = pasteboard;
        }

        if ([[dictionary objectForKey:SUOwnerKey] isEqual:encryptedDomain]) {
            ownerIndex = i;
        }
    }

    if (ownerIndex == -1) {

        // if this is nil, we haven't found anything on this device
        if (!mostRecentDictionary) {
            mostRecentDictionary = [NSMutableDictionary dictionary];
        }

        [mostRecentDictionary setObject:encryptedDomain forKey:SUOwnerKey];
        [mostRecentDictionary setObject:[NSDate date]   forKey:SUTimeStampKey];

        if ((lowestUnusedIndex < 0) || (lowestUnusedIndex >= SECURE_UDID_MAX_PASTEBOARD_ENTRIES)) {
            return nil;
        }

        usablePasteboard = [UIPasteboard pasteboardWithName:pasteboardNameForNumber(lowestUnusedIndex) create:YES];
        usablePasteboard.persistent = YES;

        [usablePasteboard setData:[NSKeyedArchiver archivedDataWithRootObject:mostRecentDictionary] forPasteboardType:SUTypeDataDictionary];
    }

    assert(usablePasteboard);

    return usablePasteboard;
}

@end
