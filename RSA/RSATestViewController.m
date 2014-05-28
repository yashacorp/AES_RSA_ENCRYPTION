//
//  RSATestViewController.m
//  RSA
//
//  Created by Jacob Sokolov on 24/05/14.
//  Copyright (c) 2014 Jacob Sokolov. All rights reserved.
//

#import <CommonCrypto/CommonCryptor.h>
#import <CommonCrypto/CommonDigest.h>
#import "RSATestViewController.h"
#import "FBEncryptorAES.h"

const size_t BUFFER_SIZE = 512;
const size_t CIPHER_BUFFER_SIZE = 4096;
const uint32_t PADDING = kSecPaddingNone;

uint8_t * plainBuffer;
uint8_t * cipherBuffer;

static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey";
static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey";

@interface RSATestViewController ()
{
    UITextField * textFieldMessage;

    UILabel * labelEncryptedMessage;
    UILabel * labelKeyRSA;
    
    UIButton * buttonEncrypt;
    UIButton * buttonDecrypt;
    
    NSMutableString * randomString;
    
    NSString * alphabet;
    NSString * encryptedMessage;
    NSString * decryptedMessage;
    
    NSMutableString * string;
    
    NSMutableString * key;
}

@end

@implementation RSATestViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
    
    [self payload];
}

- (void)payload
{
    self.view.backgroundColor = [UIColor colorWithWhite:0.98f alpha:1.0f];
    
    textFieldMessage = [[UITextField alloc]initWithFrame:CGRectMake(20, 120, 280, 30)];
    textFieldMessage.placeholder = @"Type youe message here";
    textFieldMessage.backgroundColor = [UIColor whiteColor];
    textFieldMessage.layer.borderWidth = 1.0f;
    textFieldMessage.layer.borderColor = [[UIColor lightGrayColor]CGColor];
    
    labelEncryptedMessage = [[UILabel alloc]initWithFrame:CGRectMake(20, 160, 280, 30)];
    labelEncryptedMessage.backgroundColor = [UIColor blueColor];
    labelEncryptedMessage.layer.borderWidth = 1.0f;
    labelEncryptedMessage.layer.borderColor = [[UIColor lightGrayColor]CGColor];
    labelEncryptedMessage.text = @"Message";
    
    labelKeyRSA = [[UILabel alloc]initWithFrame:CGRectMake(20, 200, 280, 30)];
    labelKeyRSA.backgroundColor = [UIColor redColor];
    labelKeyRSA.layer.borderWidth = 1.0f;
    labelKeyRSA.layer.borderColor = [[UIColor lightGrayColor]CGColor];
    labelKeyRSA.text = @"Key";
    
    buttonEncrypt = [UIButton buttonWithType:UIButtonTypeSystem];
    [buttonEncrypt setFrame:CGRectMake(40, 80, 60, 30)];
    [buttonEncrypt setTitle:@"Encrypt" forState:UIControlStateNormal];
    [buttonEncrypt setBackgroundColor:[UIColor whiteColor]];
    [buttonEncrypt.layer setBorderWidth:1.0f];
    [buttonEncrypt.layer setBorderColor:[[UIColor lightGrayColor]CGColor]];
    [buttonEncrypt addTarget:self action:@selector(encryptMessage) forControlEvents:UIControlEventTouchUpInside];
    
    buttonDecrypt = [UIButton buttonWithType:UIButtonTypeSystem];
    [buttonDecrypt setFrame:CGRectMake(220, 80, 60, 30)];
    [buttonDecrypt setTitle:@"Decrypt" forState:UIControlStateNormal];
    [buttonDecrypt setBackgroundColor:[UIColor whiteColor]];
    [buttonDecrypt.layer setBorderWidth:1.0f];
    [buttonDecrypt.layer setBorderColor:[[UIColor lightGrayColor]CGColor]];
    [buttonDecrypt addTarget:self action:@selector(decryptMessage) forControlEvents:UIControlEventTouchUpInside];
    
    [self.view addSubview:textFieldMessage];
    [self.view addSubview:labelEncryptedMessage];
    [self.view addSubview:labelKeyRSA];
    [self.view addSubview:buttonEncrypt];
    [self.view addSubview:buttonDecrypt];
    
    key = [NSMutableString stringWithFormat:@"%s", cipherBuffer];
}


// Creating random alphanumeric string


- (NSString *)randomStringWithLength:(int)length
{
    alphabet = @"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    
    randomString = [NSMutableString stringWithCapacity:length];
    
    for (int i=0; i<length; i++)
    {
        [randomString appendFormat: @"%C", [alphabet characterAtIndex: arc4random_uniform(25) % [alphabet length]]];
    }
    
    return randomString;
}


// ecnryptMessage (textField.text)


- (void)encryptMessage
{
    string = [NSMutableString stringWithFormat:@"%@", [self randomStringWithLength:25]];
    
    const char inputString = *[string UTF8String];
    
    int inputLenght = string.length;
    
    if (inputLenght > BUFFER_SIZE) inputLenght = BUFFER_SIZE-1;
    
    plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)plainBuffer, &inputString, inputLenght);
    
    [self encryptWithPublicKey:plainBuffer cipherBuffer:cipherBuffer]; // encrypting key using RSA-4096
    
    if (cipherBuffer == cipherBuffer-1 || cipherBuffer == nil)
    {
        [self encryptWithPublicKey:plainBuffer cipherBuffer:cipherBuffer];
    }
    
    encryptedMessage = [FBEncryptorAES encryptBase64String:textFieldMessage.text keyString:key separateLines:NO]; // encrypting message using AES-512 with RSA key
    
    labelEncryptedMessage.text = encryptedMessage;
    
    labelKeyRSA.text = [NSString stringWithFormat:@"%s", cipherBuffer];
    
    free(plainBuffer);
    free(cipherBuffer);
}


// decryptMessage (encryptedMessage)


- (void)decryptMessage
{
    decryptedMessage = [FBEncryptorAES decryptBase64String:encryptedMessage keyString:key];
    
    labelEncryptedMessage.text = decryptedMessage;
    
    labelKeyRSA.text = string;
}



// THIS METHODS DOWN BELOW WAS CREATED BY STACKOVERFLOW'S USER'S



- (NSString *)sha1:(NSString *)hashString
{
    const char *cStr = [hashString UTF8String];
    
    unsigned char result[CC_SHA1_DIGEST_LENGTH];
    
    CC_SHA1(cStr, strlen(cStr), result);
    
    NSString * hash = [NSString  stringWithFormat:
                       @"%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                       result[0], result[1], result[2], result[3], result[4],
                       result[5], result[6], result[7],
                       result[8], result[9], result[10], result[11], result[12],
                       result[13], result[14], result[15],
                       result[16], result[17], result[18], result[19]
                       ];
    
    return hash;
}

-(SecKeyRef)getPublicKeyRef
{
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyReference = NULL;
    
    if (publicKeyReference == NULL) {
        [self generateKeyPair:512];
        NSMutableDictionary *queryPublicKey = [[NSMutableDictionary alloc] init];
        
        // Set the public key query dictionary.
        [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
        [queryPublicKey setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
        [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
        [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
        
        
        // Get the key.
        sanityCheck = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)&publicKeyReference);
        
        
        if (sanityCheck != noErr)
        {
            publicKeyReference = NULL;
        }
        
        
        //        [queryPublicKey release];
        
    } else { publicKeyReference = publicKey; }
    
    return publicKeyReference;
}

/* Borrowed from:
 * https://developer.apple.com/library/mac/#documentation/security/conceptual/CertKeyTrustProgGuide/iPhone_Tasks/iPhone_Tasks.html
 */
- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer
{
    NSLog(@"== encryptWithPublicKey()");
    
    OSStatus status = noErr;
    
    NSLog(@"** original plain text 0: %s", plainBuffer);
    
    size_t plainBufferSize = strlen((char *)plainBuffer);
    size_t cipherBufferSize = CIPHER_BUFFER_SIZE;
    
    NSLog(@"SecKeyGetBlockSize() public = %lu", SecKeyGetBlockSize([self getPublicKeyRef]));
    //  Error handling
    // Encrypt using the public.
    status = SecKeyEncrypt([self getPublicKeyRef],
                           PADDING,
                           plainBuffer,
                           plainBufferSize,
                           &cipherBuffer[0],
                           &cipherBufferSize
                           );
    NSLog(@"encryption result code: %ld (size: %lu)", status, cipherBufferSize);
    NSLog(@"encrypted text: %s", cipherBuffer);
}

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer
{
    OSStatus status = noErr;
    
    size_t cipherBufferSize = strlen((char *)cipherBuffer);
    
    NSLog(@"decryptWithPrivateKey: length of buffer: %lu", BUFFER_SIZE);
    NSLog(@"decryptWithPrivateKey: length of input: %lu", cipherBufferSize);
    
    // DECRYPTION
    size_t plainBufferSize = BUFFER_SIZE;
    
    //  Error handling
    status = SecKeyDecrypt([self getPrivateKeyRef],
                           PADDING,
                           &cipherBuffer[0],
                           cipherBufferSize,
                           &plainBuffer[0],
                           &plainBufferSize
                           );
    NSLog(@"decryption result code: %ld (size: %lu)", status, plainBufferSize);
    NSLog(@"FINAL decrypted text: %s", plainBuffer);
    
}



- (SecKeyRef)getPrivateKeyRef {
    OSStatus resultCode = noErr;
    SecKeyRef privateKeyReference = NULL;
    //    NSData *privateTag = [NSData dataWithBytes:@"ABCD" length:strlen((const char *)@"ABCD")];
    //    if(privateKey == NULL) {
    [self generateKeyPair:512];
    NSMutableDictionary * queryPrivateKey = [[NSMutableDictionary alloc] init];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [queryPrivateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPrivateKey, (CFTypeRef *)&privateKeyReference);
    NSLog(@"getPrivateKey: result code: %ld", resultCode);
    
    if(resultCode != noErr)
    {
        privateKeyReference = NULL;
    }
    
    //        [queryPrivateKey release];
    //    } else {
    //        privateKeyReference = privateKey;
    //    }
    
    return privateKeyReference;
}


#pragma mark - View lifecycle


- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    // Return YES for supported orientations
    if ([[UIDevice currentDevice] userInterfaceIdiom] == UIUserInterfaceIdiomPhone) {
        return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
    } else {
        return YES;
    }
}

- (void)generateKeyPair:(NSUInteger)keySize {
    OSStatus sanityCheck = noErr;
    publicKey = NULL;
    privateKey = NULL;
    
    //  LOGGING_FACILITY1( keySize == 512 || keySize == 1024 || keySize == 2048, @"%d is an invalid and unsupported key size.", keySize );
    
    // First delete current keys.
    //  [self deleteAsymmetricKeys];
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * publicKeyAttr = [[NSMutableDictionary alloc] init];
    NSMutableDictionary * keyPairAttr = [[NSMutableDictionary alloc] init];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:keySize] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKey, &privateKey);
    //  LOGGING_FACILITY( sanityCheck == noErr && publicKey != NULL && privateKey != NULL, @"Something really bad went wrong with generating the key pair." );
    if(sanityCheck == noErr  && publicKey != NULL && privateKey != NULL)
    {
        NSLog(@"Successful");
    }
    //  [privateKeyAttr release];
    //  [publicKeyAttr release];
    //  [keyPairAttr release];
}


@end
