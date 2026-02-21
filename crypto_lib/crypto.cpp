#include "crypto.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>
#include <iomanip>
#include <sstream>

#ifdef _WIN32
    #include <windows.h>
    #define BUILDING_DLL
#else
    #include <unistd.h>
#endif

// Простая реализация AES-256 (для образовательных целей)
// В реальном проекте лучше использовать готовую библиотеку типа OpenSSL или Crypto++

class SimpleAES {
private:
    static const int BLOCK_SIZE = 16; // 128 бит
    static const int KEY_SIZE = 32;    // 256 бит
    static const int ROUNDS = 14;      // для AES-256
    
    unsigned char key[KEY_SIZE];
    
    // S-box для шифрования (упрощенный - в реальном AES используется таблица)
    static const unsigned char sbox[256];
    
    // Обратный S-box для дешифрования
    static const unsigned char inv_sbox[256];
    
    // Rcon для раундовых ключей
    static const unsigned char rcon[11];
    
    // Вспомогательные функции
    unsigned char xtime(unsigned char x) {
        return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
    }
    
    void add_round_key(unsigned char* state, unsigned char* round_key) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] ^= round_key[i];
        }
    }
    
    void sub_bytes(unsigned char* state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = sbox[state[i]];
        }
    }
    
    void inv_sub_bytes(unsigned char* state) {
        for (int i = 0; i < BLOCK_SIZE; i++) {
            state[i] = inv_sbox[state[i]];
        }
    }
    
    void shift_rows(unsigned char* state) {
        unsigned char temp[BLOCK_SIZE];
        
        temp[0] = state[0];
        temp[1] = state[5];
        temp[2] = state[10];
        temp[3] = state[15];
        
        temp[4] = state[4];
        temp[5] = state[9];
        temp[6] = state[14];
        temp[7] = state[3];
        
        temp[8] = state[8];
        temp[9] = state[13];
        temp[10] = state[2];
        temp[11] = state[7];
        
        temp[12] = state[12];
        temp[13] = state[1];
        temp[14] = state[6];
        temp[15] = state[11];
        
        memcpy(state, temp, BLOCK_SIZE);
    }
    
    void inv_shift_rows(unsigned char* state) {
        unsigned char temp[BLOCK_SIZE];
        
        temp[0] = state[0];
        temp[1] = state[13];
        temp[2] = state[10];
        temp[3] = state[7];
        
        temp[4] = state[4];
        temp[5] = state[1];
        temp[6] = state[14];
        temp[7] = state[11];
        
        temp[8] = state[8];
        temp[9] = state[5];
        temp[10] = state[2];
        temp[11] = state[15];
        
        temp[12] = state[12];
        temp[13] = state[9];
        temp[14] = state[6];
        temp[15] = state[3];
        
        memcpy(state, temp, BLOCK_SIZE);
    }
    
    void mix_columns(unsigned char* state) {
        for (int i = 0; i < 4; i++) {
            int idx = i * 4;
            unsigned char a0 = state[idx];
            unsigned char a1 = state[idx + 1];
            unsigned char a2 = state[idx + 2];
            unsigned char a3 = state[idx + 3];
            
            state[idx] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
            state[idx + 1] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
            state[idx + 2] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
            state[idx + 3] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
        }
    }
    
    void inv_mix_columns(unsigned char* state) {
        for (int i = 0; i < 4; i++) {
            int idx = i * 4;
            unsigned char a0 = state[idx];
            unsigned char a1 = state[idx + 1];
            unsigned char a2 = state[idx + 2];
            unsigned char a3 = state[idx + 3];
            
            state[idx] = xtime(xtime(a0 ^ a2)) ^ xtime(xtime(a1 ^ a3)) ^ 
                        xtime(a0 ^ a3) ^ a0 ^ a1 ^ a2 ^ a3;
            state[idx + 1] = xtime(xtime(a1 ^ a3)) ^ xtime(xtime(a0 ^ a2)) ^ 
                            xtime(a1 ^ a2) ^ a0 ^ a1 ^ a2 ^ a3;
            state[idx + 2] = xtime(xtime(a0 ^ a2)) ^ xtime(xtime(a1 ^ a3)) ^ 
                            xtime(a0 ^ a1) ^ a0 ^ a1 ^ a2 ^ a3;
            state[idx + 3] = xtime(xtime(a1 ^ a3)) ^ xtime(xtime(a0 ^ a2)) ^ 
                            xtime(a2 ^ a3) ^ a0 ^ a1 ^ a2 ^ a3;
        }
    }
    
public:
    SimpleAES(const unsigned char* key_data) {
        memcpy(key, key_data, KEY_SIZE);
    }
    
    void encrypt_block(const unsigned char* input, unsigned char* output) {
        unsigned char state[BLOCK_SIZE];
        memcpy(state, input, BLOCK_SIZE);
        
        // Начальный раунд
        add_round_key(state, key);
        
        // Основные раунды
        for (int round = 1; round < ROUNDS; round++) {
            sub_bytes(state);
            shift_rows(state);
            mix_columns(state);
            add_round_key(state, key + (round * BLOCK_SIZE));
        }
        
        // Финальный раунд
        sub_bytes(state);
        shift_rows(state);
        add_round_key(state, key + (ROUNDS * BLOCK_SIZE));
        
        memcpy(output, state, BLOCK_SIZE);
    }
    
    void decrypt_block(const unsigned char* input, unsigned char* output) {
        unsigned char state[BLOCK_SIZE];
        memcpy(state, input, BLOCK_SIZE);
        
        // Начальный раунд
        add_round_key(state, key + (ROUNDS * BLOCK_SIZE));
        
        // Основные раунды
        for (int round = ROUNDS - 1; round > 0; round--) {
            inv_shift_rows(state);
            inv_sub_bytes(state);
            add_round_key(state, key + (round * BLOCK_SIZE));
            inv_mix_columns(state);
        }
        
        // Финальный раунд
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, key);
        
        memcpy(output, state, BLOCK_SIZE);
    }
};

// Определение S-Box (упрощенный, но рабочий)
const unsigned char SimpleAES::sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

const unsigned char SimpleAES::inv_sbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

const unsigned char SimpleAES::rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// Глобальные переменные для хранения последней ошибки
static std::string last_error = "";
static char error_buffer[256] = {0};

// Функция для генерации IV (Initialization Vector)
void generate_iv(unsigned char* iv, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    
    for (size_t i = 0; i < size; i++) {
        iv[i] = static_cast<unsigned char>(dis(gen));
    }
}

// Функция для получения ключа из пароля (упрощенный PBKDF2)
void derive_key_from_password(const char* password, unsigned char* key, size_t key_size) {
    size_t password_len = strlen(password);
    
    // Простое хеширование пароля (в реальном проекте используйте PBKDF2)
    for (size_t i = 0; i < key_size; i++) {
        key[i] = password[i % password_len] ^ (i * 0x1B);
    }
}

// Функция шифрования файла
extern "C" DLL_EXPORT int encrypt_file(const char* input_path, const char* output_path, const char* password) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        last_error = "Не удалось открыть входной файл";
        return 1;
    }
    
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        last_error = "Не удалось создать выходной файл";
        return 2;
    }
    
    // Получаем размер файла
    input_file.seekg(0, std::ios::end);
    std::streamsize file_size = input_file.tellg();
    input_file.seekg(0, std::ios::beg);
    
    // Генерируем ключ из пароля
    unsigned char key[32];
    derive_key_from_password(password, key, 32);
    
    // Генерируем IV
    unsigned char iv[16];
    generate_iv(iv, 16);
    
    // Записываем IV в начало выходного файла (нужен для дешифровки)
    output_file.write(reinterpret_cast<char*>(iv), 16);
    
    // Создаем экземпляр шифра
    SimpleAES aes(key);
    
    // Буферы для чтения/записи
    const size_t BUFFER_SIZE = 4096;
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE];
    
    // Текущий IV для CBC режима
    unsigned char current_iv[16];
    memcpy(current_iv, iv, 16);
    
    // Читаем и шифруем файл блоками
    while (input_file.read(reinterpret_cast<char*>(input_buffer), BUFFER_SIZE) || input_file.gcount() > 0) {
        std::streamsize bytes_read = input_file.gcount();
        
        // Дополняем последний блок до 16 байт (PKCS#7 padding)
        if (bytes_read < BUFFER_SIZE) {
            size_t padding = 16 - (bytes_read % 16);
            for (int i = bytes_read; i < bytes_read + padding; i++) {
                input_buffer[i] = padding;
            }
            bytes_read += padding;
        }
        
        // Шифруем каждый 16-байтовый блок
        for (int i = 0; i < bytes_read; i += 16) {
            // XOR с предыдущим зашифрованным блоком (CBC режим)
            for (int j = 0; j < 16; j++) {
                input_buffer[i + j] ^= current_iv[j];
            }
            
            // Шифруем блок
            aes.encrypt_block(input_buffer + i, output_buffer + i);
            
            // Сохраняем зашифрованный блок как IV для следующего
            memcpy(current_iv, output_buffer + i, 16);
        }
        
        // Записываем зашифрованные данные
        output_file.write(reinterpret_cast<char*>(output_buffer), bytes_read);
    }
    
    input_file.close();
    output_file.close();
    
    last_error = "Успешно";
    return 0;
}

// Функция дешифрования файла
extern "C" DLL_EXPORT int decrypt_file(const char* input_path, const char* output_path, const char* password) {
    std::ifstream input_file(input_path, std::ios::binary);
    if (!input_file) {
        last_error = "Не удалось открыть входной файл";
        return 1;
    }
    
    std::ofstream output_file(output_path, std::ios::binary);
    if (!output_file) {
        last_error = "Не удалось создать выходной файл";
        return 2;
    }
    
    // Читаем IV из начала файла
    unsigned char iv[16];
    input_file.read(reinterpret_cast<char*>(iv), 16);
    
    if (input_file.gcount() < 16) {
        last_error = "Файл поврежден: отсутствует IV";
        return 3;
    }
    
    // Генерируем ключ из пароля
    unsigned char key[32];
    derive_key_from_password(password, key, 32);
    
    // Создаем экземпляр шифра
    SimpleAES aes(key);
    
    // Буферы для чтения/записи
    const size_t BUFFER_SIZE = 4096;
    unsigned char input_buffer[BUFFER_SIZE];
    unsigned char output_buffer[BUFFER_SIZE];
    
    // Текущий IV для CBC режима
    unsigned char current_iv[16];
    unsigned char next_iv[16];
    memcpy(current_iv, iv, 16);
    
    // Читаем и дешифруем файл блоками
    while (input_file.read(reinterpret_cast<char*>(input_buffer), BUFFER_SIZE) || input_file.gcount() > 0) {
        std::streamsize bytes_read = input_file.gcount();
        
        // Дешифруем каждый 16-байтовый блок
        for (int i = 0; i < bytes_read; i += 16) {
            // Сохраняем зашифрованный блок для следующей итерации
            if (i + 16 <= bytes_read) {
                memcpy(next_iv, input_buffer + i, 16);
            }
            
            // Дешифруем блок
            aes.decrypt_block(input_buffer + i, output_buffer + i);
            
            // XOR с IV (CBC режим)
            for (int j = 0; j < 16; j++) {
                output_buffer[i + j] ^= current_iv[j];
            }
            
            // Обновляем IV для следующего блока
            memcpy(current_iv, next_iv, 16);
        }
        
        // Убираем padding из последнего блока
        if (input_file.eof()) {
            unsigned char padding = output_buffer[bytes_read - 1];
            if (padding <= 16) {
                bytes_read -= padding;
            }
        }
        
        // Записываем расшифрованные данные
        output_file.write(reinterpret_cast<char*>(output_buffer), bytes_read);
    }
    
    input_file.close();
    output_file.close();
    
    last_error = "Успешно";
    return 0;
}

// Функция для получения последней ошибки
extern "C" DLL_EXPORT const char* get_last_error() {
    strncpy(error_buffer, last_error.c_str(), sizeof(error_buffer) - 1);
    error_buffer[sizeof(error_buffer) - 1] = '\0';
    return error_buffer;
}