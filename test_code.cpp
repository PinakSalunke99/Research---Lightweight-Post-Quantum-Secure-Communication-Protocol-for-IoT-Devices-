#include <openssl/evp.h>
#include <openssl/err.h>

#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
using namespace chrono;

// ------------------------------------------------------------
// Generic hash function using OpenSSL EVP
// ------------------------------------------------------------
vector<unsigned char> hashData(
    const string& algorithm,
    const string& input)
{
    EVP_MD* md = nullptr;

    if (algorithm == "SHA256")
        md = (EVP_MD*)EVP_sha256();
    else if (algorithm == "SHA512")
        md = (EVP_MD*)EVP_sha512();
    else if (algorithm == "SHA3-256")
        md = (EVP_MD*)EVP_sha3_256();
    else if (algorithm == "BLAKE2s-256")
        md = (EVP_MD*)EVP_blake2s256();
    else {
        throw runtime_error("Unknown hash algorithm");
    }

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    if (!ctx)
        throw runtime_error("Could not create EVP context");

    vector<unsigned char> output(EVP_MD_size(md));
    unsigned int outputLength = 0;

    if (EVP_DigestInit_ex(ctx, md, nullptr) != 1 ||
        EVP_DigestUpdate(ctx, input.data(), input.size()) != 1 ||
        EVP_DigestFinal_ex(ctx, output.data(), &outputLength) != 1)
    {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Hash operation failed");
    }

    output.resize(outputLength);

    EVP_MD_CTX_free(ctx);

    return output;
}

// ------------------------------------------------------------
// Convert hash output to hexadecimal
// ------------------------------------------------------------
string toHex(const vector<unsigned char>& data)
{
    string result;

    for (unsigned char byte : data)
    {
        char buffer[3];

        snprintf(buffer, sizeof(buffer), "%02x", byte);

        result += buffer;
    }

    return result;
}

// ------------------------------------------------------------
// Benchmark one algorithm
// ------------------------------------------------------------
void benchmark(
    const string& algorithm,
    const string& input,
    int iterations)
{
    // Warm-up
    for (int i = 0; i < 100; i++)
        hashData(algorithm, input);

    auto start = high_resolution_clock::now();

    vector<unsigned char> result;

    for (int i = 0; i < iterations; i++)
    {
        result = hashData(
            algorithm,
            input + to_string(i)
        );
    }

    auto end = high_resolution_clock::now();

    auto duration =
        duration_cast<nanoseconds>(end - start);

    double totalMs =
        duration.count() / 1e6;

    double averageUs =
        duration.count() /
        static_cast<double>(iterations) /
        1000.0;

    double throughput =
        iterations /
        (duration.count() / 1e9);

    cout << left
         << setw(15) << algorithm
         << setw(15) << totalMs
         << setw(20) << averageUs
         << setw(15) << throughput
         << setw(15) << result.size()
         << endl;
}

// ------------------------------------------------------------
// Main
// ------------------------------------------------------------
int main()
{
    const string deviceID = "IoT_DEVICE_001";
    const string password = "SecurePassword123";
    const string nonce = "ABC123456789";

    // Similar to the paper's hash-based operations:
    //
    // H(Password XOR Nonce)
    //
    // For this benchmark we concatenate the values because
    // XOR requires equal-length byte strings.

    string input =
        password + "|" +
        nonce + "|" +
        deviceID;

    const int iterations = 100000;

    cout << "Hash Benchmark for IoT Protocol\n";
    cout << "Iterations: "
         << iterations << "\n\n";

    cout << left
         << setw(15) << "Algorithm"
         << setw(15) << "Total(ms)"
         << setw(20) << "Avg(us)"
         << setw(15) << "Hash/sec"
         << setw(15) << "Output(bytes)"
         << endl;

    cout << string(80, '-') << endl;

    benchmark(
        "SHA256",
        input,
        iterations
    );

    benchmark(
        "SHA512",
        input,
        iterations
    );

    benchmark(
        "SHA3-256",
        input,
        iterations
    );

    benchmark(
        "BLAKE2s-256",
        input,
        iterations
    );

    // Show one example output
    cout << "\nExample SHA-256 output:\n";

    auto result =
        hashData("SHA256", input);

    cout << toHex(result) << endl;

    return 0;
}
