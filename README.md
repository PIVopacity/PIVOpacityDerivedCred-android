# Secure Derived Credential Demo -- Android

### About ###
[Exponent, Inc.](http://www.exponent.com) has developed a proof of concept demonstration to show the feasibility of using a derived credential on an NFC-enabled phone for physical access control and authentication.  This demonstration implements a protocol called OPACITY (as defined in [NIST Special Publication 800-73-4](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-73-4.pdf)) to rapidly establish encrypted contactless communications between an NFC-enabled Android phone and three other types of devices: PIV/CAC cards, a contactless reader connected to a computer, and other NFC-enabled phones.

A video and description of the demostration app functionality can be found on [youtube](https://youtu.be/ftn8-Cth554).

A credential is derived on the phone by generating a key pair, associating user information from the PIV/CAC credential with the new key pair, and signing the new credential with the original card's authentication certificate.  All card to mobile communication is protected by the OPACITY secure messaging tunnel.  The public/private key pair for the new derived credential is generated in the protected hardware of the phone, if available, and stored in the native Android KeyStore.  

Once the derived credential is on the phone, it can be used to authenticate to other devices using full cryptographic challenge/response operations to prove possession. In all authentication examples, device-to-device communication is encrypted by establishing an OPACITY channel.  To simulate a physical access control system (PACS), the phone is presented to a contactless reader connected to a computer.  When the reader senses a ''card'' in the field (in this case the NFC-enabled phone), the computer attempts to select the PIV application on the card/phone.  When the phone detects the SELECT PIV application command, the native Android Host APDU service automatically directs all subsequent communications to the derived credential.  Using the native service means that the user does not need to select any application in order for the process to proceed; they simply need to unlock the phone.  The credential is then authenticated using a cryptographic challenge/response (RSA or ECDSA) and other means (e.g., checking the expiration date, verifying the signature on the certificate from the original credential, etc.).  This entire process, including establishing the OPACITY secure encrypted channel, takes approximately 2 seconds.

The demonstration app also extends the authentication process for full-secrecy, privacy enhanced phone-to-phone identity authentication over NFC. 

This research was conducted under contract with the U.S Department of Homeland Security (DHS) Science and Technology Directorate (S&T) and sponsored by Kantara Initiative Inc.  Any opinions contained herein are those of the author and do not necessarily reflect those of [DHS S&T](https://www.dhs.gov/science-and-technology).


### License ###
Software distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND


See [LICENSE](https://github.com/PIVopacity/PIVOpacityDerivedCred-android/blob/master/LICENSE.txt)


### Security ###
This project was developed to demonstrate communication functionality only and is not meant to serve as a fully secured example of the communication protocol.
