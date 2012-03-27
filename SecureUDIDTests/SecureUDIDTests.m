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

@interface SecureUDIDTests : SenTestCase

@end

@implementation SecureUDIDTests

/*
 Tests the output from the UDIDForDomain:salt: method.
 */
- (void)testUDIDForDomain {
    // Confirm we get a UDID back.
    NSString *udid = [SecureUDID UDIDForDomain:@"com.example.myapp" salt:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(udid, @"udid should not be nil");
    
    // Confirm we get the same UDID back.
    NSString *sameUDID = [SecureUDID UDIDForDomain:@"com.example.myapp" salt:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(sameUDID, @"sameUDID should not be nil");
    STAssertEqualObjects(udid, sameUDID, @"udid and sameUDID should be equal");
    
    // Confirm we get a different UDID since we are using a different domain.
    NSString *newUDID = [SecureUDID UDIDForDomain:@"com.example.myapp.udid" salt:@"superSecretCodeHere!@##%#$#%$^"];
    STAssertNotNil(newUDID, @"newUDID should not be nil");
    STAssertFalse([newUDID isEqualToString:udid], @"newUDID and udid should not be equal");
}

@end
