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
#import <CommonCrypto/CommonDigest.h>

#define SECURE_UDID_MAX_PASTEBOARD_ENTRIES (100)

NSString *const SUUIDDefaultIdentifier   = @"00000000-0000-0000-0000-000000000000";

NSString *const SUUIDTypeDataDictionary  = @"public.secureudid";
NSString *const SUUIDTimeStampKey        = @"SUUIDTimeStampKey";
NSString *const SUUIDOwnerKey            = @"SUUIDOwnerKey";
NSString *const SUUIDLastAccessedKey     = @"SUUIDLastAccessedKey";
NSString *const SUUIDIdentifierKey       = @"SUUIDIdentifierKey";
NSString *const SUUIDOptOutKey           = @"SUUIDOptOutKey";
NSString *const SUUIDPastboardFileFormat = @"org.secureudid-%d";

NSData *cryptorToData(CCOperation operation, NSData *value, NSData *key);
NSString *cryptorToString(CCOperation operation, NSData *value, NSData *key);
NSString *pasteboardNameForNumber(NSInteger number);
UIPasteboard *pasteboardForEncryptedDomain(NSData *encryptedDomain);

@implementation SecureUDID

/*
 Returns a unique id for the device, sandboxed to the domain and salt provided.

 Example usage:
 #import "SecureUDID.h"

 NSString *udid = [SecureUDID UDIDForDomain:@"com.example.myapp" salt:@"superSecretCodeHere!@##%#$#%$^"];

 */
+ (NSString *)UDIDForDomain:(NSString *)domain salt:(NSString *)salt {
    // Salt the domain to make the crypt keys affectively unguessable.
    NSData *domainAndSalt = [[NSString stringWithFormat:@"%@%@", domain, salt] dataUsingEncoding:NSUTF8StringEncoding];
    
    // Compute a SHA1 of the salted domain to standardize its length for AES-128
    uint8_t digest[kCCKeySizeAES128] = {0};
    CC_SHA1(domainAndSalt.bytes, domainAndSalt.length, digest);
    NSData *key = [NSData dataWithBytes:digest length:kCCKeySizeAES128];
    
    // Encrypt the salted domain key and load the pasteboard on which to store data
    NSData *encryptedDomain = cryptorToData(kCCEncrypt, [domain dataUsingEncoding:NSUTF8StringEncoding], key);
    UIPasteboard *pasteboard = pasteboardForEncryptedDomain(encryptedDomain);
    if (!pasteboard) {
        removeAllSecureUDIDData();
        return SUUIDDefaultIdentifier;
    }

    // Read the storage dictionary out of the pasteboard data, or create a new one
    NSMutableDictionary *topLevelDictionary = nil;
    id pasteboardData = [pasteboard dataForPasteboardType:SUUIDTypeDataDictionary];
    if (pasteboardData) {
        pasteboardData = [NSKeyedUnarchiver unarchiveObjectWithData:pasteboardData];

        // check for the opt-out flag and return the default identifier if we find it
        if ([[pasteboardData objectForKey:SUUIDOptOutKey] boolValue] == YES) {
            removeAllSecureUDIDData();
            return SUUIDDefaultIdentifier;
        }

        topLevelDictionary = [NSMutableDictionary dictionaryWithDictionary:pasteboardData];
    } else {
        topLevelDictionary = [NSMutableDictionary dictionary];
    }

    // Attempt to get the owner's dictionary.  Should we get back nil from the encryptedDomain key, we'll still
    // get a valid, empty mutable dictionary
    NSMutableDictionary *ownerDictionary = [NSMutableDictionary dictionaryWithDictionary:[topLevelDictionary objectForKey:encryptedDomain]];
    [topLevelDictionary setObject:ownerDictionary forKey:encryptedDomain];

    // set our last access time and claim ownership for this 
    NSDate* lastAccessDate = [NSDate date];
    [ownerDictionary    setObject:lastAccessDate  forKey:SUUIDLastAccessedKey];
    [topLevelDictionary setObject:lastAccessDate  forKey:SUUIDTimeStampKey];
    [topLevelDictionary setObject:encryptedDomain forKey:SUUIDOwnerKey];
    
    NSString *identifier     = nil;
    NSData   *identifierData = [ownerDictionary objectForKey:SUUIDIdentifierKey];
    if (identifierData) {
        identifier = cryptorToString(kCCDecrypt, identifierData, key);
    } else {
        // Otherwise, create a new RFC-4122 Version 4 UUID
        // http://en.wikipedia.org/wiki/Universally_unique_identifier
        CFUUIDRef uuid = CFUUIDCreate(kCFAllocatorDefault);
        identifier = [(NSString*)CFUUIDCreateString(kCFAllocatorDefault, uuid) autorelease];
        CFRelease(uuid);
        
        // Encrypt it for storage.
        NSData *data = cryptorToData(kCCEncrypt, [identifier dataUsingEncoding:NSUTF8StringEncoding], key);
        
        [ownerDictionary setObject:data forKey:SUUIDIdentifierKey];
    }
    
    // always write out the pasteboard, to record our updates
    [pasteboard setData:[NSKeyedArchiver archivedDataWithRootObject:topLevelDictionary]
      forPasteboardType:SUUIDTypeDataDictionary];
    
    return identifier;
}

/*
 Applies the operation (encrypt or decrypt) to the NSData value with the provided NSData key
 and returns the value as NSData.
 */
NSData *cryptorToData(CCOperation operation, NSData *value, NSData *key) {
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
 Applies the operation (encrypt or decrypt) to the NSData value with the provided NSData key
 and returns the value as an NSString.
 */
NSString *cryptorToString(CCOperation operation, NSData *value, NSData *key) {
    return [[[NSString alloc] initWithData:cryptorToData(operation, value, key) encoding:NSUTF8StringEncoding] autorelease];
}

void removeAllSecureUDIDData(void) {
    NSDictionary* optoutPlaceholder;
    NSData*       optoutData;
    
    optoutPlaceholder = [NSDictionary dictionaryWithObject:[NSNumber numberWithBool:YES] forKey:SUUIDOptOutKey];
    optoutData        = [NSKeyedArchiver archivedDataWithRootObject:optoutPlaceholder];
    
    for (NSInteger i = 0; i < SECURE_UDID_MAX_PASTEBOARD_ENTRIES; ++i) {
        UIPasteboard* pasteboard;
        
        pasteboard = [UIPasteboard pasteboardWithName:pasteboardNameForNumber(i) create:NO];
        if (pasteboard) {
            [pasteboard setData:optoutData forPasteboardType:SUUIDTypeDataDictionary];
        }
    }
}

/*
 Returns an NSString formatted with the supplied number.
 */
NSString *pasteboardNameForNumber(NSInteger number) {
    return [NSString stringWithFormat:SUUIDPastboardFileFormat, number];
}

/*
 SecureUDID leverages UIPasteboards to persistently store its data.
 UIPasteboards marked as 'persistent' have the following attributes:
 - They persist across application relaunches, device reboots, and OS upgrades.
 - They are destroyed when the application that created them is deleted from the device.

 To protect against the latter case, SecureUDID leverages multiple pasteboards (up to
 SECURE_UDID_MAX_PASTEBOARD_ENTRIES), creating one for each distinct domain/app that
 leverages the system. The permanence of SecureUDIDs increases exponentially with the
 number of apps that use it.

 Returns a pasteboard for the encrypted domain. If a pasteboard for the domain is not found a new one is created.
 */
UIPasteboard *pasteboardForEncryptedDomain(NSData *encryptedDomain) {
    UIPasteboard*        usablePasteboard;
    NSInteger            lowestUnusedIndex;
    NSDate*              mostRecentDate;
    NSMutableDictionary* mostRecentDictionary;
    
    usablePasteboard     = nil;
    lowestUnusedIndex    = INTMAX_MAX;
    mostRecentDate       = [NSDate distantPast];
    mostRecentDictionary = nil;
    
    // The array of SecureUDID pasteboards can be sparse, since any number of
    // apps may have been deleted. To find a pasteboard owned by the the current
    // domain, iterate all of them.
    for (NSInteger i = 0; i < SECURE_UDID_MAX_PASTEBOARD_ENTRIES; ++i) {
        UIPasteboard* pasteboard;
        NSDate*       modifiedDate;
        NSDictionary* dictionary;
        NSData*       pasteboardData;
        
        // If the pasteboard could not be found, notate that this is the first unused index.
        pasteboard = [UIPasteboard pasteboardWithName:pasteboardNameForNumber(i) create:NO];
        if (!pasteboard) {
            if (lowestUnusedIndex == -1) {
                lowestUnusedIndex = i;
            }
            
            continue;
        }
        
        // If it was found, load and validate its payload
        pasteboardData = [pasteboard valueForPasteboardType:SUUIDTypeDataDictionary];
        if (!pasteboardData) {
            // corrupted slot
            if (lowestUnusedIndex == -1) {
                lowestUnusedIndex = i;
            }
            
            continue;
        }
        
        // Check the 'modified' timestamp of this pasteboard
        dictionary   = [NSKeyedUnarchiver unarchiveObjectWithData:pasteboardData];
        modifiedDate = [dictionary valueForKey:SUUIDTimeStampKey];
        
        if ([[dictionary objectForKey:SUUIDOptOutKey] boolValue] == YES) {
            return nil;
        }
        
        // Hold a copy of the data if this is the newest we've found so far.
        if ([modifiedDate compare:mostRecentDate] == NSOrderedDescending) {
            mostRecentDate       = modifiedDate;
            mostRecentDictionary = [NSMutableDictionary dictionaryWithDictionary:dictionary];
        }
        
        // Finally, notate if this is the pasteboard owned by the requesting domain.
        if ([[dictionary objectForKey:SUUIDOwnerKey] isEqual:encryptedDomain]) {
            usablePasteboard = pasteboard;
        }
    }
    
    // If no pasteboard is owned by this domain, establish a new one to increase the
    // likelihood of permanence.
    if (!usablePasteboard) {
        // Unless there are no available slots, pick one
        if ((lowestUnusedIndex < 0) || (lowestUnusedIndex >= SECURE_UDID_MAX_PASTEBOARD_ENTRIES)) {
            return nil;
        }
        
        // Copy the most recent data over if possible
        if (!mostRecentDictionary) {
            mostRecentDictionary = [NSMutableDictionary dictionary];
        }
        
        // Create and save the pasteboard.
        usablePasteboard = [UIPasteboard pasteboardWithName:pasteboardNameForNumber(lowestUnusedIndex) create:YES];
        usablePasteboard.persistent = YES;
    }
    
    // Write it back to the pasteboard, so the next steps will merge data.
    [usablePasteboard setData:[NSKeyedArchiver archivedDataWithRootObject:mostRecentDictionary]
            forPasteboardType:SUUIDTypeDataDictionary];
    
    return usablePasteboard;
}

@end
