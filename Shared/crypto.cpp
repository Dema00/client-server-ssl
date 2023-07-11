#include "header/crypto.h"

void handleErrors(){
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    DEBUG_MSG(std::cout<<"ENC KEY: \n" << BIO_dump_fp (stdout, (const char *)key, 64) <<std::endl;);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();
    
    /*
     * Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /*
     * Finalise the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
        handleErrors();
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    DEBUG_MSG(std::cout<<"DEC KEY: \n" << BIO_dump_fp (stdout, (const char *)key, 64) <<std::endl;);

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    /*
     * Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits
     */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_xts(), NULL, key, iv))
        handleErrors();

    /*
     * Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary.
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /*
     * Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;
    
    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

        DEBUG_MSG(std::cout << "finished decrypt" << std::endl;);

    return plaintext_len;
}

void hmac(const unsigned char* key, int key_len, const unsigned char* data,
    int data_len, unsigned char* md, unsigned int* md_len){
    HMAC(EVP_sha256(), (const void*)key, key_len,
                    data, data_len,
                    md, md_len);
}

int rsa_encrypt(EVP_PKEY **pub_key, unsigned char *plaintext, int plaintext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *ciphertext) {
        
    EVP_CIPHER_CTX *ctx;
	int ciphertext_len;
	int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_SealInit(ctx, EVP_aes_256_xts(), &encrypted_key,
		&encrypted_key_len, iv, pub_key, 1))
		handleErrors();

    // Use a separate buffer for ciphertext
    unsigned char *temp_ciphertext = (unsigned char *)malloc(plaintext_len + EVP_MAX_BLOCK_LENGTH);
    if (temp_ciphertext == NULL) {
        handleErrors();
    }

    if(1 != EVP_SealUpdate(ctx, temp_ciphertext, &len, plaintext, plaintext_len+1))
		handleErrors();
	ciphertext_len = len;

    if(1 != EVP_SealFinal(ctx, temp_ciphertext + len, &len)) handleErrors();
	ciphertext_len += len;

    // Copy the ciphertext to the output buffer
    std::memcpy(ciphertext, temp_ciphertext, ciphertext_len);

    // Clean up
    free(temp_ciphertext);
	EVP_CIPHER_CTX_free(ctx);

        DEBUG_MSG(std::cout << "finished encrypt" << std::endl;);

	return ciphertext_len;    
}

int rsa_decrypt(EVP_PKEY *priv_key, unsigned char *ciphertext, int ciphertext_len,
	unsigned char *encrypted_key, int encrypted_key_len, unsigned char *iv, unsigned char *plaintext) {
    
    EVP_CIPHER_CTX *ctx;
	int plaintext_len;
	int len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if(1 != EVP_OpenInit(ctx, EVP_aes_256_xts(), encrypted_key,
		encrypted_key_len, iv, priv_key)){
            std::cerr << "failed to init RSA decrypt" << std::endl;
		    handleErrors();
    }

    if(1 != EVP_OpenUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		handleErrors();
	plaintext_len = len;

    if(1 != EVP_OpenFinal(ctx, plaintext + len, &len)) handleErrors();
	plaintext_len += len;

	/* Clean up */
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_len;

    }

std::pair<EVP_PKEY*, EVP_PKEY*> generate_rsa_keypair(){
    auto bne = BN_new();         //refer to https://www.openssl.org/docs/man1.0.2/man3/bn.html
    BN_set_word(bne, RSA_F4);

    int bits = 2048;
    RSA *r = RSA_new();
    RSA_generate_key_ex(r, bits, bne, NULL);  //here we generate the RSA keys

    //we use a memory BIO to store the keys
    BIO *bp_public  = BIO_new(BIO_s_mem());PEM_write_bio_RSAPublicKey (bp_public, r);
    BIO *bp_private = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bp_private, r, NULL, NULL, 0, NULL, NULL);

    auto pri_len = BIO_pending(bp_private);   //once the data is written to a 
                                              //memory/file BIO, we get the size
    auto pub_len = BIO_pending(bp_public);
    char *pri_key = (char*) malloc(pri_len + 1);
    char *pub_key = (char*) malloc(pub_len + 1);

    BIO_read(bp_private, pri_key, pri_len);   //now we read the BIO into a buffer
    BIO_read(bp_public, pub_key, pub_len);

    pri_key[pri_len] = '\0';
    pub_key[pub_len] = '\0';

    //printf("\n%s\n:\n%s\n", pri_key, pub_key);fflush(stdout);  //now we print the keys 
    //to stdout (DO NOT PRINT private key in production code, this has to be a secret)

    BIO *pbkeybio = NULL;
    pbkeybio=BIO_new_mem_buf((void*) pub_key, pub_len);  //we create a buffer BIO 
                                     //(this is different from the memory BIO created earlier)
    BIO *prkeybio = NULL;
    prkeybio=BIO_new_mem_buf((void*) pri_key, pri_len);

    RSA *pb_rsa = NULL;
    RSA *p_rsa = NULL;

    pb_rsa = PEM_read_bio_RSAPublicKey(pbkeybio, &pb_rsa, NULL, NULL);  //now we read the 
                                                                   //BIO to get the RSA key
    p_rsa = PEM_read_bio_RSAPrivateKey(prkeybio, &p_rsa, NULL, NULL);

    EVP_PKEY *evp_pbkey = EVP_PKEY_new();  //we want EVP keys , openssl libraries 
                         //work best with this type, https://wiki.openssl.org/index.php/EVP
    EVP_PKEY_assign_RSA(evp_pbkey, pb_rsa);

    EVP_PKEY *evp_prkey = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(evp_prkey, p_rsa);

    //clean up
    free(pri_key);free(pub_key);
    BIO_free_all(bp_public);BIO_free_all(bp_private);
    BIO_free(pbkeybio);BIO_free(prkeybio);
    BN_free(bne);
    RSA_free(r);

    return {evp_pbkey,evp_prkey};
}

void verify_cert(X509* ca_cert, X509_CRL* crl, X509* cert) {

    int ret;
    X509_STORE* store = X509_STORE_new();
    if(!store) { std::cerr << "Error: X509_STORE_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_add_cert(store, ca_cert);
    if(ret != 1) { std::cerr << "Error: X509_STORE_add_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_add_crl(store, crl);
    if(ret != 1) { std::cerr << "Error: X509_STORE_add_crl returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK);
    if(ret != 1) { std::cerr << "Error: X509_STORE_set_flags returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

    X509_STORE_CTX* certvfy_ctx = X509_STORE_CTX_new();
    if(!certvfy_ctx) { std::cerr << "Error: X509_STORE_CTX_new returned NULL\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_STORE_CTX_init(certvfy_ctx, store, cert, NULL);
    if(ret != 1) { std::cerr << "Error: X509_STORE_CTX_init returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }
    ret = X509_verify_cert(certvfy_ctx);
    if(ret != 1) { std::cerr << "Error: X509_verify_cert returned " << ret << "\n" << ERR_error_string(ERR_get_error(), NULL) << "\n"; exit(1); }

        DEBUG_MSG(
            char* tmp = X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0);
            char* tmp2 = X509_NAME_oneline(X509_get_issuer_name(cert), NULL, 0);
            std::cout << "Certificate of \"" << tmp << "\" (released by \"" << tmp2 << "\") verified successfully\n";
            free(tmp);
            free(tmp2);
        );

    X509_STORE_CTX_free(certvfy_ctx);
    X509_STORE_free(store);
}

void verify_signature(unsigned char* sig, int sig_size,
    unsigned char* to_verify, int to_verify_size, X509* cert){
    int ret;
    const EVP_MD* md = EVP_sha256();
    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ std::cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

    // verify the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
    ret = EVP_VerifyInit(md_ctx, md);
    if(ret == 0){ std::cerr << "Error: EVP_VerifyInit returned " << ret << "\n"; exit(1); }
    ret = EVP_VerifyUpdate(md_ctx, to_verify, to_verify_size);  
    if(ret == 0){ std::cerr << "Error: EVP_VerifyUpdate returned " << ret << "\n"; exit(1); }
    ret = EVP_VerifyFinal(md_ctx, sig, sig_size, X509_get_pubkey(cert));
    if(ret == -1){ // it is 0 if invalid signature, -1 if some other error, 1 if success.
       std::cerr << "Error: EVP_VerifyFinal returned " << ret << " (invalid signature?)\n";
       exit(1);
    }else if(ret == 0){
       std::cerr << "Error: Invalid signature!\n";
       exit(1);
    }

    // print the successful signature verification to screen:
        DEBUG_MSG(std::cout << "The Signature has been correctly verified! The message is authentic!\n";);

    // deallocate data:
    EVP_MD_CTX_free(md_ctx);
    //X509_free(cacert); // already deallocated by X509_STORE_free()
    //X509_CRL_free(crl); // already deallocated by X509_STORE_free()
}

int sign(unsigned char* plaintext, int plaintext_len, EVP_PKEY* priv_key, unsigned char* signed_msg){
    int ret;

    // declare some useful variables:
    const EVP_MD* md = EVP_sha256();

    // create the signature context:
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if(!md_ctx){ std::cerr << "Error: EVP_MD_CTX_new returned NULL\n"; exit(1); }

    // allocate buffer for signature:
    //unsigned char* sgnt_buf = (unsigned char*)malloc(EVP_PKEY_size(priv_key));
    //if(!sgnt_buf) { std::cerr << "Error: malloc returned NULL (signature too big?)\n"; exit(1); }

    // sign the plaintext:
    // (perform a single update on the whole plaintext, 
    // assuming that the plaintext is not huge)
    ret = EVP_SignInit(md_ctx, md);
    if(ret == 0){ std::cerr << "Error: EVP_SignInit returned " << ret << "\n"; exit(1); }
    ret = EVP_SignUpdate(md_ctx, plaintext, plaintext_len);
    if(ret == 0){ std::cerr << "Error: EVP_SignUpdate returned " << ret << "\n"; exit(1); }
    unsigned int sgnt_size;
    ret = EVP_SignFinal(md_ctx, signed_msg, &sgnt_size, priv_key);
    if(ret == 0){ std::cerr << "Error: EVP_SignFinal returned " << ret << "\n"; exit(1); }

    // delete the digest and the private key from memory:
    EVP_MD_CTX_free(md_ctx);

    return sgnt_size;

}

void sha256(const unsigned char* input, int len, unsigned char* out){
    //unsigned char hash[SHA256_DIGEST_LENGTH];

    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, input, len);
    SHA256_Final(out, &sha256);
        DEBUG_MSG(std::cout<<"HASH: \n" << BIO_dump_fp (stdout, (const char *)out, SHA256_DIGEST_LENGTH) <<std::endl;);
}
