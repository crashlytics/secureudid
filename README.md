![image](http://www.crashlytics.com/blog/wp-content/uploads/2012/03/SecureUDID.png)

####What is SecureUDID?
SecureUDID is an open-source sandboxed UDID solution aimed at solving the main privacy issues that caused Apple to deprecate UDIDs.

SecureUDIDs have the following attributes:

1. Developers can still differentiate between devices as if they were still using a UDID, but only within apps they control.

2. User privacy is protected since developers are fundamentally prevented from accessing the same UDID as another developer. This greatly limits the scope of any potential leaks.

3. End-users can globally opt-out of SecureUDID collection across all applications and services that use it.

####How do I use it?
 
    #import "SecureUDID.h"

    NSString *domain = @"com.example.myapp"
    NSString *salt = @"superSecretCodeHere!@##%#$#%$^"
    NSString *udid = [SecureUDID UDIDForDomain:domain salt:salt];
    // The returned udid is a 36 character (128 byte + 4 dashes) string that is unique for that domain, salt, and device tuple.


####FAQ

#####Who is behind SecureUDID?
The team at Crashlytics needed to address the UDID situation while still adhering to privacy concerns. Crashlytics wanted to contribute this back to the community.

#####What about OpenUDID?
AppsFire unveiled OpenUDID back in September as one of the initial responses to Apple's deprecation of UDIDs and our very own Sam Robbins was its second contributor. Since then, we've spent time outlining what would make a more secure UDID, and the changes required turned out to be significant. Establishing a single identifier per device is fundamentally no different than a MAC address or Apple's UDID - the privacy concerns are the same.

#####Can I use SecureUDID with other UDID frameworks, including OpenUDID?
Yes, SecureUDID does not conflict with any other UDID implementation or framework.

#####What about Android?
We chose to initially implement SecureUDID on iOS, but the concepts can be applied equally to Android, Windows Phone, and other platforms. We welcome contributions!

#####How can I get involved?
Fork the crashlytics/secureudid project on GitHub, file issues, implement fixes, and submit pull requests!
