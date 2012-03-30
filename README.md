![image](http://www.crashlytics.com/blog/wp-content/uploads/2012/03/SecureUDID.png)

####What is SecureUDID?
SecureUDID is an open-source sandboxed device identifier solution aimed at solving the main privacy issues that caused Apple to deprecate UDIDs.

SecureUDIDs have the following attributes:

1. Developers can still differentiate between devices as if they were still using a UDID, but only within apps they control.

2. User privacy is protected since developers are fundamentally prevented from accessing the same UDID as another developer. This greatly limits the scope of any potential leaks.

3. End-users can globally opt-out of SecureUDID collection across all applications and services that use it.

####How do I use it?

    #import "SecureUDID.h"

    NSString *domain     = @"com.example.myapp"
    NSString *key        = @"difficult-to-guess-key"
    NSString *identifier = [SecureUDID UDIDForDomain:domain usingKey:key];
    // The returned identifier is a 36 character (128 byte + 4 dashes) string that is unique for that domain, key, and device tuple.


####FAQ

#####Who is behind SecureUDID?
The team at Crashlytics needed to address the UDID situation while still adhering to privacy concerns. Crashlytics wanted to contribute this back to the community.

#####Is this a true UDID replacement?
SecureUDID has two properties that you should know about before you use it.  First, as indicated above, the identifier is not derived from hardware attributes.  Second, the persistence of an identifier cannot be guaranteed in all situations.  This means that, while unlikely, it is technically possible for two distinct devices to report the same identifier, and for the same device to report different identifiers.  Consider this carefully in your application.  Here is a list of situations where this identifier will not exhibit the uniqueness/persistence of a traditional UDID.

- The user has opted-out of the SecureUDID system, in which case you will receive a well-formed string of zeroes.
- Device A is backed up and then restored to Device B, which is an identical model. This is common when someone breaks their phone, for example, and is likely desirable: you will receive Device A's SecureUDID.
- The SecureUDID data is removed, via user intervention, UIPasteboard data purge, or by a malicious application.
- The SecureUDID backing store becomes corrupt.
- All SecureUDID applications are uninstalled from a device, followed by a UIPasteboard data purge.

#####What about OpenUDID?
AppsFire unveiled OpenUDID back in September as one of the initial responses to Apple's deprecation of UDIDs and our very own Sam Robbins was its second contributor. Since then, we've spent time outlining what would make a more secure UDID, and the changes required turned out to be significant. Establishing a single identifier per device is fundamentally no different than a MAC address or Apple's UDID - the privacy concerns are the same.

#####Can I use SecureUDID with other UDID frameworks, including OpenUDID?
Yes, SecureUDID does not conflict with any other UDID implementation or framework.

#####What about Android?
We chose to initially implement SecureUDID on iOS, but the concepts can be applied equally to Android, Windows Phone, and other platforms. We welcome contributions!

#####How can I get involved?
Fork the crashlytics/secureudid project on GitHub, file issues, implement fixes, and submit pull requests!

#####Version History

March 30, 2012 - 1.1

- Greatly improved robustness to backing store corruption/correctness
- Groundwork for Opt-Out application interface
- Additional API for Opt-Out query and background identifier derivation
- Support for unlimited number of installed SecureUDID applications
- Renamed API to de-emphasize the notion of a salt
- Improved detection of backup/restore

March 27, 2012 - 1.0

- Per-Owner dictionary implementation to support Opt-Out functionality
- Addressed an issue that could result in pasteboard overwriting

March 26, 2012 - 0.9

- First public release
