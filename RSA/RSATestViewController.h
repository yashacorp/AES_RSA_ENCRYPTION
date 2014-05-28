//
//  RSATestViewController.h
//  RSA
//
//  Created by Jacob Sokolov on 24/05/14.
//  Copyright (c) 2014 Jacob Sokolov. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface RSATestViewController : UIViewController
{
    SecKeyRef publicKey;
    SecKeyRef privateKey;
    
    NSData *publicTag;
    NSData *privateTag;
}

- (void)encryptWithPublicKey:(uint8_t *)plainBuffer cipherBuffer:(uint8_t *)cipherBuffer;

- (void)decryptWithPrivateKey:(uint8_t *)cipherBuffer plainBuffer:(uint8_t *)plainBuffer;

- (void)generateKeyPair:(NSUInteger)keySize;

- (void)encryptMessage;

- (void)decryptMessage;

- (SecKeyRef)getPublicKeyRef;

- (SecKeyRef)getPrivateKeyRef;

@end
