//
//  SecureUDIDTests.m
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

#import <SenTestingKit/SenTestingKit.h>
#import "SecureUDID.h"

#import <UIKit/UIKit.h>

// Stuff we need from SecureUDID.m
#define SUUID_SCHEMA_VERSION        (1)
#define SUUID_MAX_STORAGE_LOCATIONS (64)

extern NSString *const SUUIDTypeDataDictionary;
extern NSString *const SUUIDOwnerKey;
extern NSString *const SUUIDIdentifierKey;
extern NSString *const SUUIDOptOutKey;
extern NSString *const SUUIDTimeStampKey;
extern NSString *const SUUIDModelHashKey;
extern NSString *const SUUIDSchemaVersionKey;

extern void          SUUIDMarkOptedOut(void);
extern void          SUUIDMarkOptedIn(void);
extern NSString     *SUUIDPasteboardNameForNumber(NSInteger number);
extern NSDictionary *SUUIDDictionaryForStorageLocation(NSInteger number);
extern void          SUUIDWriteDictionaryToStorageLocation(NSInteger number, NSDictionary* dictionary);
extern void          SUUIDDeleteStorageLocation(NSInteger number);
extern void          SUUIDRemoveAllSecureUDIDData(void);

// End of stuff

@interface SecureUDIDTests : SenTestCase

- (void)setUp;

@end

@implementation SecureUDIDTests

- (void)setUp {
    
    // clear out any previous pasteboards
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        SUUIDDeleteStorageLocation(i);
    }
}

- (void)writeUnverifiedData:(NSDictionary*)dictionary toStorageLocation:(NSInteger)location {
    UIPasteboard* pasteboard;
    
    pasteboard = [UIPasteboard pasteboardWithName:SUUIDPasteboardNameForNumber(location) create:YES];
    if (!pasteboard) {
        return;
    }
    
    pasteboard.persistent = YES;
    
    [pasteboard setData:[NSKeyedArchiver archivedDataWithRootObject:dictionary]
      forPasteboardType:SUUIDTypeDataDictionary];
}

/*
 Tests the output from the UDIDForDomain:usingKey: method.
 */
- (void)testUDIDForDomain {
    // Confirm we get a UDID back.
    NSString *udid = [SecureUDID UDIDForDomain:@"com.example.myapp" usingKey:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(udid, @"udid should not be nil");
    
    // Confirm we get the same UDID back.
    NSString *sameUDID = [SecureUDID UDIDForDomain:@"com.example.myapp" usingKey:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(sameUDID, @"sameUDID should not be nil");
    STAssertEqualObjects(udid, sameUDID, @"udid and sameUDID should be equal");
    
    // Confirm we get a different UDID since we are using a different domain.
    NSString *newUDID = [SecureUDID UDIDForDomain:@"com.example.myapp.udid" usingKey:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(newUDID, @"newUDID should not be nil");
    STAssertFalse([newUDID isEqualToString:udid], @"newUDID and udid should not be equal");
}

- (void)testFirstDomainGetsFirstLocation {
    NSDictionary* dictionary;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp" usingKey:@"example key"];
    
    dictionary = SUUIDDictionaryForStorageLocation(0);
    STAssertNotNil(dictionary, @"The first location should have a valid dictionary");
    STAssertNotNil([dictionary objectForKey:[dictionary objectForKey:SUUIDOwnerKey]], @"The owner should have an owner dictionary");
    
    for (NSInteger i = 1; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        dictionary = SUUIDDictionaryForStorageLocation(i);
        
        STAssertNil(dictionary, @"All other locations should be nil");
    }
}

- (void)testSecondDomainDoesNotOverwriteFirst {
    NSDictionary* dictionary1;
    NSDictionary* dictionary2;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    [SecureUDID UDIDForDomain:@"com.example.myapp-2" usingKey:@"example key 2"];
    
    dictionary1 = SUUIDDictionaryForStorageLocation(0);
    dictionary2 = SUUIDDictionaryForStorageLocation(1);
    
    STAssertEquals(5, (int)[dictionary1 count], @"First dictionary should have four meta-data keys + one owner");
    STAssertNotNil([dictionary1 objectForKey:SUUIDOwnerKey], @"An owner should be set");
    STAssertNotNil([dictionary1 objectForKey:SUUIDTimeStampKey], @"A timestamp should be set too");
    
    STAssertEquals(6, (int)[dictionary2 count], @"Second dictionary should have four meta-data keys + two owners");
    STAssertNotNil([dictionary2 objectForKey:SUUIDOwnerKey], @"An owner should be set");
    STAssertNotNil([dictionary2 objectForKey:SUUIDTimeStampKey], @"A timestamp should be set too");
    
    STAssertFalse([[dictionary1 objectForKey:SUUIDOwnerKey] isEqual:[dictionary2 objectForKey:SUUIDOwnerKey]], @"Owners should not be equal");
    
    STAssertNotNil([dictionary1 objectForKey:[dictionary1 objectForKey:SUUIDOwnerKey]], @"The owner of the first should be represented in the first");
    STAssertNil([dictionary1 objectForKey:[dictionary2 objectForKey:SUUIDOwnerKey]], @"The owner of the second should NOT be represented in the first");
    
    STAssertNotNil([dictionary2 objectForKey:[dictionary1 objectForKey:SUUIDOwnerKey]], @"The owner of the first should be represented in the second");
    STAssertNotNil([dictionary2 objectForKey:[dictionary2 objectForKey:SUUIDOwnerKey]], @"The owner of the second should be represented in the second");
}

- (void)testSecondDomainCopiedToFirstOnAccess {
    NSDictionary* dictionary1;
    NSDictionary* dictionary2;
    NSData*       owner1;
    NSData*       owner2;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    [SecureUDID UDIDForDomain:@"com.example.myapp-2" usingKey:@"example key 2"];
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    dictionary1 = SUUIDDictionaryForStorageLocation(0);
    dictionary2 = SUUIDDictionaryForStorageLocation(1);
    
    owner1 = [dictionary1 objectForKey:SUUIDOwnerKey];
    owner2 = [dictionary2 objectForKey:SUUIDOwnerKey];
    
    STAssertNotNil([dictionary1 objectForKey:owner1], @"Owner1 should be represented in the first");
    STAssertNotNil([dictionary1 objectForKey:owner2], @"Owner2 should be represented in the first");
}

- (void)testMaximumPlusOneAccess {
    NSDictionary* firstDictionary;
    NSDictionary* dictionary;
    
    // This takes a long time to execute.  The storage algorithm is inefficient, so calling it
    // many times in a row isn't great.  The typical case, where an application generates one (or just a few)
    // identifiers is much better.
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        [SecureUDID UDIDForDomain:[NSString stringWithFormat:@"com.example.myapp-%d", i] usingKey:@"example key"];
    }
    
    // that should be the max
    firstDictionary = SUUIDDictionaryForStorageLocation(0);
    dictionary      = SUUIDDictionaryForStorageLocation(SUUID_MAX_STORAGE_LOCATIONS-1);
    STAssertNotNil(dictionary, @"The last storage location should have an entry");
    
    // add the plus one
    [SecureUDID UDIDForDomain:@"com.example.myapp-last-plus-one" usingKey:@"example key"];
    
    // this should overwrite the firstDictionary location
    dictionary = SUUIDDictionaryForStorageLocation(0);
    STAssertFalse([[dictionary objectForKey:SUUIDOwnerKey] isEqual:[firstDictionary objectForKey:SUUIDOwnerKey]], @"Owners should not be equal");
    STAssertEquals(SUUID_MAX_STORAGE_LOCATIONS + 1 + 4, (int)[dictionary count], @"All owners, plus four meta-data entries, should be present");
}

- (void)testCorruptionViaMissingTimestamp {
    NSMutableDictionary* dictionary;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    dictionary = [NSMutableDictionary dictionaryWithDictionary:SUUIDDictionaryForStorageLocation(0)];
    
    [dictionary removeObjectForKey:SUUIDTimeStampKey];
    
    [self writeUnverifiedData:dictionary toStorageLocation:0];
    
    STAssertNil(SUUIDDictionaryForStorageLocation(0), @"Location should be removed");
}

- (void)testCorruptionViaMissingOwner {
    NSMutableDictionary* dictionary;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    dictionary = [NSMutableDictionary dictionaryWithDictionary:SUUIDDictionaryForStorageLocation(0)];
    
    [dictionary removeObjectForKey:SUUIDOwnerKey];
    
    [self writeUnverifiedData:dictionary toStorageLocation:0];
    
    STAssertNil(SUUIDDictionaryForStorageLocation(0), @"Location should be removed");
}

- (void)testCorruptionViaDecryptionFailureOfIndentifier {
    NSString*            identifier;
    NSMutableDictionary* dictionary;
    NSMutableDictionary* ownerDictionary;
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    STAssertFalse([identifier isEqualToString:SUUIDDefaultIdentifier], @"Id should not be the default");
    
    dictionary      = [NSMutableDictionary dictionaryWithDictionary:SUUIDDictionaryForStorageLocation(0)];
    ownerDictionary = [NSMutableDictionary dictionaryWithDictionary:[dictionary objectForKey:[dictionary objectForKey:SUUIDOwnerKey]]];
    
    [ownerDictionary setObject:[NSData data]   forKey:SUUIDIdentifierKey]; // set a bogus identifier
    [dictionary      setObject:ownerDictionary forKey:[dictionary objectForKey:SUUIDOwnerKey]];
    
    [self writeUnverifiedData:dictionary toStorageLocation:0];
    
    // after all that, get the id back so we can check it
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    STAssertEqualObjects(SUUIDDefaultIdentifier, identifier, @"The default id should come back on decryption failure");
    STAssertNil(SUUIDDictionaryForStorageLocation(0), @"... and the storage location should get blown away");
}

- (void)testNewUDIDGeneratedWithModelHashMismatch {
    NSMutableDictionary* dictionary;
    NSString*            identifier1;
    NSString*            identifier2;
    
    identifier1 = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    dictionary = [NSMutableDictionary dictionaryWithDictionary:SUUIDDictionaryForStorageLocation(0)];
    
    [dictionary setObject:[NSData data] forKey:SUUIDModelHashKey];
    
    SUUIDWriteDictionaryToStorageLocation(0, dictionary);
    STAssertNotNil(SUUIDDictionaryForStorageLocation(0), @"Mismatched model hash should still pass verification");
    
    identifier2 = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertNil(SUUIDDictionaryForStorageLocation(1), @"Should still write to first location");
    STAssertFalse([identifier1 isEqual:identifier2], @"IDs should not be the same");
}

- (void)testOptOutProvidesDefaultIdentifier {
    NSString* identifier;
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertFalse([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should not be the default");
    
    SUUIDMarkOptedOut();
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should now be the default");
}

- (void)testOptOutPreservesGeneratedIDs {
    NSDictionary* dictionary;
    NSString*     identifier;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-2" usingKey:@"example key 2"];
    
    SUUIDMarkOptedOut();
    
    STAssertTrue([SecureUDID isOptedOut], @"Should now be opted out");
    
    // All storage locations should have been updated here
    dictionary = SUUIDDictionaryForStorageLocation(0);
    
    STAssertEquals(7, (int)[dictionary count], @"There should be five meta-data keys and two owners");
    
    SUUIDMarkOptedIn();
    
    STAssertEqualObjects(identifier, [SecureUDID UDIDForDomain:@"com.example.myapp-2" usingKey:@"example key 2"], @"Identifiers should remain the same");
}

- (void)testOptOutPreservesOwners {
    NSData* owner1Before;
    NSData* owner1After;
    NSData* owner2Before;
    NSData* owner2After;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    [SecureUDID UDIDForDomain:@"com.example.myapp-2" usingKey:@"example key 2"];
    
    owner1Before = [SUUIDDictionaryForStorageLocation(0) objectForKey:SUUIDOwnerKey];
    owner2Before = [SUUIDDictionaryForStorageLocation(1) objectForKey:SUUIDOwnerKey];
    
    STAssertFalse([owner1Before isEqualToData:owner2Before], @"Owners should be distinct");
    
    SUUIDMarkOptedOut();
    
    owner1After = [SUUIDDictionaryForStorageLocation(0) objectForKey:SUUIDOwnerKey];
    owner2After = [SUUIDDictionaryForStorageLocation(1) objectForKey:SUUIDOwnerKey];
    
    STAssertEqualObjects(owner1Before, owner1After, @"Onwer 1 should be the same");
    STAssertEqualObjects(owner2Before, owner2After, @"Onwer 1 should be the same");
}

- (void)testOptInWithNoData {
    NSString* identifier;
    
    SUUIDMarkOptedIn();
    
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        STAssertNil(SUUIDDictionaryForStorageLocation(i), @"No data should be present if you opt-in without any ids established");
    }
    
    STAssertFalse([SecureUDID isOptedOut], @"Should not be opted out");
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertFalse([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should not be the default");
}

- (void)testOptOutWithNoData {
    NSString* identifier;
    
    SUUIDMarkOptedOut();
    
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        STAssertNotNil(SUUIDDictionaryForStorageLocation(i), @"No data should be present if you opt-in without any ids established");
    }
    
    STAssertTrue([SecureUDID isOptedOut], @"Should be opted out");
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should be the default");
}

- (void)testOptOutTwiceWithNoData {
    NSString* identifier;
    
    SUUIDMarkOptedOut();
    SUUIDMarkOptedOut();
    
    STAssertTrue([SecureUDID isOptedOut], @"Should be opted out");
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should be the default");
}

- (void)testOptOutTwice {
    NSString* identifier;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    SUUIDMarkOptedOut();
    SUUIDMarkOptedOut();
    
    STAssertTrue([SecureUDID isOptedOut], @"Should be opted out");
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should be the default");
}

- (void)testOptOutFollowedByDeleteShouldHaveOptOutInAllLocations {
    NSString* identifier;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    SUUIDMarkOptedOut();
    
    SUUIDRemoveAllSecureUDIDData();
    
    STAssertTrue([SecureUDID isOptedOut], @"Should be opted out");
    
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        NSDictionary* dictionary;
        
        dictionary = SUUIDDictionaryForStorageLocation(i);
        STAssertTrue([[dictionary objectForKey:SUUIDOptOutKey] boolValue], @"Opt-Out flag should be set");
    }
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should be the default");
}

- (void)testDeleteFollowedByOptOutShouldHaveOptOutInAllLocations {
    NSString* identifier;
    
    [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    SUUIDRemoveAllSecureUDIDData();
    
    SUUIDMarkOptedOut();
    
    STAssertTrue([SecureUDID isOptedOut], @"Should be opted out");
    
    for (NSInteger i = 0; i < SUUID_MAX_STORAGE_LOCATIONS; ++i) {
        NSDictionary* dictionary;
        
        dictionary = SUUIDDictionaryForStorageLocation(i);
        STAssertTrue([[dictionary objectForKey:SUUIDOptOutKey] boolValue], @"Opt-Out flag should be set");
    }
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Identifier should be the default");
}

- (void)testNewerSchemaIsUntouched {
    NSString*            identifier;
    NSMutableDictionary* dictionary;
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    STAssertFalse([identifier isEqualToString:SUUIDDefaultIdentifier], @"Should not be the default id");
    
    dictionary = [NSMutableDictionary dictionaryWithDictionary:SUUIDDictionaryForStorageLocation(0)];
    
    [dictionary setObject:[NSNumber numberWithInt:SUUID_SCHEMA_VERSION+1] forKey:SUUIDSchemaVersionKey];
    
    [self writeUnverifiedData:dictionary toStorageLocation:0]; // save it to the store
    
    identifier = [SecureUDID UDIDForDomain:@"com.example.myapp-1" usingKey:@"example key 1"];
    STAssertTrue([identifier isEqualToString:SUUIDDefaultIdentifier], @"Should be the default when schemas don't match");
    
    STAssertTrue([dictionary isEqual:SUUIDDictionaryForStorageLocation(0)], @"And the dictionary should be identical");
}

@end
