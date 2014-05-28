//
//  RSATestViewController.h
//  RSA
//
//  Created by Jacob Sokolov on 21/05/14.
//  Copyright (c) 2014 Jacob Sokolov. All rights reserved.
//

#import <UIKit/UIKit.h>

#import <Security/Security.h>

@interface RSAEngine : UIViewController
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    
    NSData *publicTag;
    NSData *privateTag;
}

- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer;
- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer;
- (void)generateKeyPair:(NSUInteger)keySize;
- (void)encryptMessage:(NSString *)message;
- (void)decryptMessage:(NSString *)message;
- (void)testAsymmetricEncryptionAndDecryption;

- (SecKeyRef)getPublicKeyRef;
- (SecKeyRef)getPrivateKeyRef;

@property (strong,nonatomic) NSString * encryptedMessage;
@property (strong,nonatomic) NSString * decryptedMessage;

@property uint8_t plainBuffer;
@property uint8_t cipherBuffer;

@end
