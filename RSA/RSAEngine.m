//
//  RSATestViewController.m
//  RSA
//
//  Created by Jacob Sokolov on 21/05/14.
//  Copyright (c) 2014 Jacob Sokolov. All rights reserved.
//

const size_t BUFFER_SIZE = 512;
const size_t CIPHER_BUFFER_SIZE = 4096;
const uint32_t PADDING = kSecPaddingNone;

uint8_t * cipherBuffer;
uint8_t * plainBuffer;

static const UInt8 publicKeyIdentifier[] = "com.apple.sample.publickey";
static const UInt8 privateKeyIdentifier[] = "com.apple.sample.privatekey";

#import "RSAEngine.h"
#import "FBEncryptorAES.h"
#import <CommonCrypto/CommonCrypto.h>

@interface RSAEngine ()
{
    NSString * alphabet;
    NSString * string;
    
    NSMutableString * randomString;
}

@end

@implementation RSAEngine

@synthesize encryptedMessage, decryptedMessage;

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
    
    return publicKeyReference; }

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Release any cached data, images, etc that aren't in use.
}




- (void)testAsymmetricEncryptionAndDecryption
{
    uint8_t *plainBuffer;
    uint8_t *cipherBuffer;
    uint8_t *decryptedBuffer;
    
    string = [NSString stringWithFormat:@"%@", [self randomStringWithLength:22]];
    
    const char inputString = *[string UTF8String];
    
    int inputLenght = string.length;
    
    // TODO: this is a hack since i know inputString length will be less than BUFFER_SIZE
    if (inputLenght > BUFFER_SIZE) inputLenght = BUFFER_SIZE-1;
    
    plainBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    cipherBuffer = (uint8_t *)calloc(CIPHER_BUFFER_SIZE, sizeof(uint8_t));
    decryptedBuffer = (uint8_t *)calloc(BUFFER_SIZE, sizeof(uint8_t));
    
    strncpy( (char *)plainBuffer, &inputString, inputLenght);
    
    NSLog(@"init() plainBuffer: %s", plainBuffer);
    //NSLog(@"init(): sizeof(plainBuffer): %d", sizeof(plainBuffer));
    [self encryptWithPublicKey:(UInt8 *)plainBuffer cipherBuffer:cipherBuffer];
    NSLog(@"encrypted data: %s", cipherBuffer);
    //NSLog(@"init(): sizeof(cipherBuffer): %d", sizeof(cipherBuffer));
    [self decryptWithPrivateKey:cipherBuffer plainBuffer:decryptedBuffer];
    NSLog(@"decrypted data: %s", decryptedBuffer);
    //NSLog(@"init(): sizeof(decryptedBuffer): %d", sizeof(decryptedBuffer));
    NSLog(@"====== /second test =======================================");
    
    free(plainBuffer);
    free(cipherBuffer);
    free(decryptedBuffer);
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



- (void)viewDidLoad
{
    [super viewDidLoad];
    // Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [super viewDidUnload];
    // Release any retained subviews of the main view.
    // e.g. self.myOutlet = nil;
}

- (void)viewWillAppear:(BOOL)animated
{
    [super viewWillAppear:animated];
    privateTag = [[NSData alloc] initWithBytes:privateKeyIdentifier length:sizeof(privateKeyIdentifier)];
    publicTag = [[NSData alloc] initWithBytes:publicKeyIdentifier length:sizeof(publicKeyIdentifier)];
    [self testAsymmetricEncryptionAndDecryption];
    
}

- (void)viewDidAppear:(BOOL)animated
{
    [super viewDidAppear:animated];
}

- (void)viewWillDisappear:(BOOL)animated
{
    [super viewWillDisappear:animated];
}

- (void)viewDidDisappear:(BOOL)animated
{
    [super viewDidDisappear:animated];
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