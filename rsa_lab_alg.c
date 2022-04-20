#include <math.h>
#include <stdio.h>
#include <stdint.h>

#define PRIME_NUMS_SIZE 50
int16_t prime_numbers[PRIME_NUMS_SIZE] = {2,3,5,7,11,13,
17,19,23,29,31,37,41,43,47,53,59,61,67,71,
73,79,83,89,97,101,103,107,109,113,127,131,137,139,149,
151,157,163,167,173,179,181,191,193,197,199,211,223,
227,229 }; // first 50 prime numbers table

// asnwears codes for user
enum answears {
	QUIT,
	G_ALGO,
	E_ALGO,
	D_ALGO,
	HELP,
	NO_ANSWEAR
};

// error code control type
typedef enum {
	ERR_OK,
	ERR_FAIL,
	ERR_ARG,
	ERR_NULL_PTR,
	ERR_WRONG_ANSWEAR
} err_code_t;


#define RETURN_IF_ERR(err) do {    \
    if ((err) != ERR_OK)           \
        return (err);              \
    } while (0)

#define RETURN_IF_ERR_MES(err, err_mes) do {    \
    if ((err) != ERR_OK) {           	        \
    	fprintf(stderr, err_mes);				\
        return (err);}                          \
    } while (0)

// type of the data used in algorithms

#define MAX_NUM_SIZE 10 
typedef struct rsa_data {
	int64_t p;
	int64_t q;
	int64_t e;
	int64_t n;
	int64_t f;
	int64_t d;

	int64_t original_num;
	int64_t original_nums[MAX_NUM_SIZE];
	uint8_t nums_size;
	int64_t cyphered_num;
	int64_t decrypted_num;
	int64_t decrypted_nums[MAX_NUM_SIZE];


	// flags to check the state of runned algorithms
	uint8_t G_runned;
	uint8_t E_runned;
	uint8_t D_runned;
} rsa_data_t;


uint8_t is_prime(int64_t num)
{
	uint16_t i = 0;
	int16_t prime_num = 0; 
	while (1) {
		prime_num = prime_numbers[i++];
		if (prime_num < sqrt(num)) {
			if ((num % prime_num) == 0) {
				return 0;
			}
		} else {
			return 1; // number is prime
		}
	}
	return 0; // never happen
}
// Euclid algo to find relatively prime numbers
int64_t gcd(int64_t x, int64_t y)
{
	return y ? gcd(y, x%y) : x;
}

// exponentional modulo function. Formula: (base ^ exp) % mod
int64_t powmod(int64_t base, int64_t exp, int64_t mod)
{
	int64_t res = 1;

	while (exp != 0) {
		if ((exp & 1) != 0) {
			res = (1ll * res * base) % mod;
		}

		base = (1ll * base * base) % mod;
		exp >>= 1;
	}
	
	return res;
}

// choose number D - decryption key from E and Phi
// formula: ed = 1(mod (Phi))
int64_t find_d(int64_t e, int64_t phi)
{
	int64_t d = 1;
	for (int64_t i = 1; i < phi; i++)
	{
		if ((i * e) % phi == 1)
		{
			d = i;
			break;
		}
	}
	return d;
}

// get the number from user
err_code_t get_num(int64_t *num)
{
	if (!num) {
		fprintf(stderr, "NULL num ptr\n");
		return ERR_ARG;
	}
	scanf("%ld", num);
	printf("Your number = %ld\n", *num);
	return ERR_OK;
}

err_code_t get_nums_to_decrypt(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}

	printf("Enter your numbers to decrypt, but no more than %d\n", MAX_NUM_SIZE);
	printf("According to the RSA algo, number has to be no more than %ld (N)\n",
		rsa_data->n);
	printf("if you want to stop entering the numbers enter 0\n");

	for (int i = 0; i < MAX_NUM_SIZE; ++i) {
		printf("Enter number%d to  be decrypted: ", i + 1);
		scanf("%ld", &rsa_data->decrypted_nums[i]);
		if (rsa_data->decrypted_nums[i] == 0) {
			fprintf(stderr, "ERROR: You've finished numbers for decryption\n");
			return ERR_OK;
		}
		if (rsa_data->decrypted_nums[i] > rsa_data->n) {
			fprintf(stderr, "ERROR: You've entered incorrect number, finish\n");
			return ERR_WRONG_ANSWEAR;
		}
		rsa_data->nums_size++;
	}

	printf("Last number entered, quit procedure of numbers data for decryption\n");
	return err;
}

err_code_t get_nums_to_encrypt(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}

	printf("Enter your numbers to encrypt, but no more than %d\n", MAX_NUM_SIZE);
	printf("According to the RSA algo, number has to be no more than %ld (N)\n",
		rsa_data->n);
	printf("if you want to stop entering the numbers enter 0\n");

	for (int i = 0; i < MAX_NUM_SIZE; ++i) {
		printf("Enter number%d to  be encrypted: ", i + 1);
		scanf("%ld", &rsa_data->original_nums[i]);
		if (rsa_data->original_nums[i] == 0) {
			fprintf(stderr, "ERROR: You've finished numbers for encryption\n");
			return ERR_OK;
		}
		if (rsa_data->original_nums[i] > rsa_data->n) {
			fprintf(stderr, "ERROR: You've entered incorrect number, finish\n");
			return ERR_WRONG_ANSWEAR;
		}
		rsa_data->nums_size++;
	}

	printf("Last number entered, quit procedure of numbers data for encryption\n");
	return err;
}

// function to encrypt numbers entered before
err_code_t encrypt_nums(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}

	printf("\nEncryption ...\n");
	for (int i = 0; i < rsa_data->nums_size; ++i) {
		printf("Encrypt number: %ld\n", rsa_data->original_nums[i]);
		rsa_data->decrypted_num = powmod(rsa_data->original_nums[i], rsa_data->e, rsa_data->n);
		printf("Result of encryption: %ld\n", rsa_data->decrypted_num);
	}
	rsa_data->nums_size = 0;
	return err;
}

// function to decrypt numbers entered before
err_code_t decrypt_nums(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}

	printf("\nDecryption ...\n");
	for (int i = 0; i < rsa_data->nums_size; ++i) {
		printf("Decrypt number: %ld\n", rsa_data->decrypted_nums[i]);
		rsa_data->decrypted_num = powmod(rsa_data->decrypted_nums[i], rsa_data->d, rsa_data->n);
		printf("Result of decryption: %ld\n", rsa_data->decrypted_num);
	}
	rsa_data->nums_size = 0;
	return err;
}
// fix number to prime
err_code_t fix_to_prime(int64_t *num)
{
	if (!num) {
		fprintf(stderr, "NULL num ptr\n");
		return ERR_ARG;
	}

	if (is_prime(*num)) {
		printf("Your number is prime\n");
	} else {
		printf("Your number is not prime, let's fix it\n");

		while (!is_prime(*num)) {
			(*num)++;
		}
		printf("Its better to use number %ld (it's prime), fixed to use it\n", (*num));
	}
	return ERR_OK;
}

err_code_t G_algo(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}

	printf("G_algo stared\n");
	printf("Enter the first number (P) (has to be prime) for keygen algo: ");
	err = get_num(&rsa_data->p);
	RETURN_IF_ERR_MES(err, "Failed to get P\n");
	fix_to_prime(&rsa_data->p);

	printf("Enter the second number (Q) (has to be prime) for keygen algo: ");
	err = get_num(&rsa_data->q);
	RETURN_IF_ERR_MES(err, "Failed to get Q\n");
	fix_to_prime(&rsa_data->q);

	printf("Programm will use these numbers as p and q for encryption(%ld, %ld)\n",
	 rsa_data->p, rsa_data->q);

	rsa_data->n = rsa_data->p * rsa_data->q;
	rsa_data->f = (rsa_data->p - 1)*(rsa_data->q - 1);
	printf("Your Phi = (p -1)(q - 1) number is %ld\n", rsa_data->f);

	printf ("Enter the number E: ");
	err = get_num(&rsa_data->e);
	RETURN_IF_ERR_MES(err, "Failed to get E\n");
	// check if (Phi = (p -1)(q - 1)) and e are relatively prime numbers
	// Euclid algo
	for (int i = rsa_data->e; i < rsa_data->f; i++) {
		if (gcd(rsa_data->f, i) != 1)
			rsa_data->e++;
		else {
			rsa_data->e = i;
			break;
		}
	}
	printf("Your public key(e, n) = (%ld, %ld)\n", rsa_data->e, rsa_data->n);

	//d = 1/e % f;
	rsa_data->d = find_d(rsa_data->e, rsa_data->f); // find private key
	printf("Your private key d = %ld\n", rsa_data->d);
	if (err == ERR_OK) {
		printf("G algorithm run success\n");
		rsa_data->G_runned = 1; // set to check for next algos
	} else {

	}

	printf("\n\n\n------------------------------------------------------------\n\n\n");
	return err;
}

err_code_t E_algo(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}
	printf("E_algo stared\n");
	if (rsa_data->G_runned) {
		uint64_t answear = 3;
		printf("Choose your answear:\n"
		"1 - enter new public key(e,n)\n"
		"0 - use generated before with G algorithm\n"
		"Answer: ");
		err = get_num(&answear);
		RETURN_IF_ERR_MES(err, "Failed to get answear\n");

		if ((answear < 0) || (answear > 1)) {
			err = ERR_WRONG_ANSWEAR;
			RETURN_IF_ERR_MES(err, "Your asnwer is wrong, quit algo\n");
		}
		if (answear) {
			printf ("Enter the number E: ");
			err = get_num(&rsa_data->e);
			RETURN_IF_ERR_MES(err, "Failed to get E\n");
			printf ("Enter the number N: ");
			err = get_num(&rsa_data->n);
			RETURN_IF_ERR_MES(err, "Failed to get N\n");
		}
	} else {
			printf ("Enter new public key(e,n) to be used in E algo\n");
			printf ("Enter the number E: ");
			err = get_num(&rsa_data->e);
			RETURN_IF_ERR_MES(err, "Failed to get E\n");
			printf ("Enter the number N: ");
			err = get_num(&rsa_data->n);
			RETURN_IF_ERR_MES(err, "Failed to get N\n");
	}

	err = get_nums_to_encrypt(rsa_data);
	RETURN_IF_ERR_MES(err, "ERROR: Failed get_nums_to_encrypt, exit algorithm\n");

	err = encrypt_nums(rsa_data);
	RETURN_IF_ERR_MES(err, "ERROR: Failed encrypt_nums, exit algorithm\n");

	rsa_data->E_runned = 1;
	printf("\n\n\n------------------------------------------------------------\n\n\n");
	return err;
}

err_code_t D_algo(rsa_data_t *rsa_data)
{
	err_code_t err = ERR_OK;
	if (!rsa_data) {
		fprintf(stderr, "NULL ptr in rsa_data param\n");
		return ERR_ARG;
	}
	printf("E_algo stared\n");
	if (rsa_data->G_runned) {
		uint64_t answear = 3;
		printf("Choose your answear:\n"
		"1 - enter new private key(d,n)\n"
		"0 - use generated before with G algorithm\n"
		"Answer: ");
		err = get_num(&answear);
		RETURN_IF_ERR_MES(err, "Failed to get answear\n");

		if ((answear < 0) || (answear > 1)) {
			err = ERR_WRONG_ANSWEAR;
			RETURN_IF_ERR_MES(err, "Your answear is wrong, quit algo\n");
		}
		if (answear) {
			printf ("Enter the number D: ");
			err = get_num(&rsa_data->d);
			RETURN_IF_ERR_MES(err, "Failed to get D\n");

			printf ("Enter the number N: ");
			err = get_num(&rsa_data->n);
			RETURN_IF_ERR_MES(err, "Failed to get N\n");
		}
	} else {
			printf("Enter new private key(d,n), to be used in D algorithm\n");
			printf ("Enter the number D: ");
			err = get_num(&rsa_data->d);
			RETURN_IF_ERR_MES(err, "Failed to get D\n");

			printf ("Enter the number N: ");
			err = get_num(&rsa_data->n);
			RETURN_IF_ERR_MES(err, "Failed to get N\n");
	}

	get_nums_to_decrypt(rsa_data);
	decrypt_nums(rsa_data);

	printf("\n\n\n------------------------------------------------------------\n\n\n");
	return err;
}

void print_help(void)
{
	printf("What algo you wan't to run?\n");
	printf("Possible candidates are:\n"
		"%d - G algorithm\n"
		"%d - E algorithm\n"
		"%d - D algorithm\n"
		"%d - quit Programm\n"
		"%d - print help one more time\n",
		 G_ALGO, E_ALGO, D_ALGO, QUIT, HELP );
}

void get_answear(int64_t *ans)
{
	printf("Answear: ");
	int err = scanf("%ld", ans);
	if (err < 1) {
		while (getchar()!='\n'); // clean input buf
		fprintf(stderr, "You've entered incorrect answear\n");
   		*ans = NO_ANSWEAR;
	}
}

int main(int argc, char const *argv[])
{
	int64_t answear = NO_ANSWEAR;
	rsa_data_t rsa_data = {};
	while(answear != QUIT) {
		print_help();
		get_answear(&answear);
		switch (answear)
		{
			case G_ALGO:
			G_algo(&rsa_data);
			break;
			case E_ALGO:
			E_algo(&rsa_data);
			break;
			case D_ALGO:
			D_algo(&rsa_data);
			break;
			case HELP:
			print_help();
			break;
			case QUIT:
			printf("You've decided to exit the program, pa-pa!\n");
			return 0;
			break;
			case NO_ANSWEAR:
			print_help();
			break;
			default:
			printf("Incorrect answer, try again, i'll show you help menu\n");
			answear = NO_ANSWEAR;
			print_help();
			break;
		}
	}
	return 0;
}