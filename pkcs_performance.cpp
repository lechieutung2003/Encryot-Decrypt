#include <iostream>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <string>
#include <chrono> // Thư viện đo thời gian

using namespace std;
using namespace std::chrono;

// Hàm mũ lũy thừa đồng dư
long long modPow(long long base, long long exp, long long mod)
{
    long long result = 1;
    base = base % mod;
    while (exp > 0)
    {
        if (exp % 2 == 1)
            result = (result * base) % mod;
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

// Hàm tính GCD
long long gcd(long long a, long long b)
{
    return (b == 0) ? a : gcd(b, a % b);
}

// Hàm tìm số nghịch đảo modulo
long long modInverse(long long x, long long m)
{
    for (long long i = 1; i < m; i++)
    {
        if ((x * i) % m == 1)
            return i;
    }
    return -1;
}

// Hàm mã hóa/giải mã đơn giản thông điệp (XOR với khóa chung)
string simpleEncryptDecrypt(string message, long long key)
{
    string result = message;
    for (size_t i = 0; i < message.size(); i++)
    {
        result[i] ^= key % 256; // XOR từng ký tự với khóa
    }
    return result;
}

string generateRandomString(int length)
{
    const string chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()";
    string result = "";

    for (int i = 0; i < length; ++i)
    {
        // Tạo chỉ số ngẫu nhiên để lấy ký tự từ chuỗi `chars`
        int index = rand() % chars.size();
        result += chars[index];
    }

    return result;
}

int main()
{
    srand(time(nullptr));

    // --- Diffie-Hellman ---
    long long p = 10857109713; // Số nguyên tố
    long long g = 5;           // Cơ số nguyên thủy

    // Khóa bí mật của A và B
    long long privateA = rand() % (p - 2) + 1;
    long long privateB = rand() % (p - 2) + 1;

    cout << "Private Key A: " << privateA << endl;
    cout << "Private Key B: " << privateB << endl;

    // Tính khóa công khai của A và B
    long long publicA = modPow(g, privateA, p);
    long long publicB = modPow(g, privateB, p);

    cout << "Public Key A: " << publicA << endl;
    cout << "Public Key B: " << publicB << endl;

    // Tính khóa chung DH
    long long sharedSecretA = modPow(publicB, privateA, p);
    long long sharedSecretB = modPow(publicA, privateB, p);

    cout << "Shared Secret DH: " << sharedSecretA << endl;

    // --- RSA ---
    long long p_rsa = 61, q_rsa = 53;
    long long n = p_rsa * q_rsa;
    long long phi = (p_rsa - 1) * (q_rsa - 1);

    long long e = 17;
    while (gcd(e, phi) != 1)
    {
        e++;
    }

    long long d = modInverse(e, phi);

    cout << "\nPhi(n): " << phi << endl;
    cout << "Public Key (e, n): (" << e << ", " << n << ")" << endl;
    cout << "Private Key (d, n): (" << d << ", " << n << ")" << endl;
    // Mã hóa khóa DH bằng RSA
    long long encryptedShared = modPow(sharedSecretA, e, n);
    cout << "Encrypted DH Key by RSA: " << encryptedShared << endl;

    // Giải mã khóa DH
    long long decryptedShared = modPow(encryptedShared, d, n);
    cout << "Decrypted DH Key by RSA: " << decryptedShared << endl;

    // --- Gửi thông điệp ---

    srand(time(0));
    string message = generateRandomString(3000000);

    // string message = "Hi!";
    // string extendedMessage;
    // for (int i = 0; i < 100; ++i)
    // {
    //     extendedMessage += message;
    // }
    // message = extendedMessage;
    // cout << "\nOriginal Message: " << message << endl;

    // Mã hóa thông điệp bằng khóa chung DH
    auto start = high_resolution_clock::now(); // Bắt đầu đo thời gian
    string encryptedMessage = simpleEncryptDecrypt(message, decryptedShared);
    auto end = high_resolution_clock::now(); // Kết thúc đo thời gian
    auto duration = duration_cast<microseconds>(end - start);
    // cout << "Encrypted Message: " << encryptedMessage << endl;
    cout << "Encryption Time: " << duration.count() << " microseconds" << endl;

    // Giải mã thông điệp
    start = high_resolution_clock::now(); // Bắt đầu đo thời gian
    string decryptedMessage = simpleEncryptDecrypt(encryptedMessage, decryptedShared);
    end = high_resolution_clock::now(); // Kết thúc đo thời gian
    duration = duration_cast<microseconds>(end - start);
    // cout << "Decrypted Message: " << decryptedMessage << endl;
    cout << "Decryption Time: " << duration.count() << " microseconds" << endl;

    return 0;
}
