#include "crypto.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <cstring>
#include <random>

#ifdef _WIN32
    #include <windows.h>
    #define BUILDING_DLL
#endif

// Простейший XOR шифр для тестирования
class SimpleXOR {
private:
    unsigned char key[32];
    
public:
    SimpleXOR(const unsigned char* key_data) {
        memcpy(key, key_data, 32);
    }
    
    void encrypt_block(const unsigned char* input, unsigned char* output, size_t size) {
        for (size_t i = 0; i < size; i++) {
            output[i] = input[i] ^ key[i % 32];
        }
    }
    
    void decrypt_block(const unsigned char* input, unsigned char* output, size_t size) {
        for (size_t i = 0; i < size; i++) {
            output[i] = input[i] ^ key[i % 32];
        }
    }
};

// Глобальные переменные
static std::string last_error = "";
static char error_buffer[256] = {0};

// Генерация IV
void generate_iv(unsigned char* iv, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (size_t i = 0; i < size; i++) {
        iv[i] = dis(gen);
    }
}

// Получение ключа из пароля (упрощённо)
void derive_key_from_password(const char* password, unsigned char* key, size_t key_size) {
    size_t password_len = strlen(password);
    for (size_t i = 0; i < key_size; i++) {
        key[i] = password[i % password_len] ^ (i * 0x1B);
    }
}

// Функция шифрования
extern "C" DLL_EXPORT int encrypt_file(const char* input_path, const char* output_path, const char* password) {
    // Открываем файлы
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
    
    // Генерируем ключ и IV
    unsigned char key[32];
    unsigned char iv[16];
    derive_key_from_password(password, key, 32);
    generate_iv(iv, 16);
    
    // Записываем IV в начало
    output_file.write(reinterpret_cast<char*>(iv), 16);
    
    // Записываем размер оригинального файла
    output_file.write(reinterpret_cast<char*>(&file_size), sizeof(file_size));
    
    // Создаем шифр
    SimpleXOR cipher(key);
    
    // Буфер для чтения
    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char encrypted[BUFFER_SIZE];
    
    // Шифруем и записываем
    while (input_file.good()) {
        input_file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        std::streamsize bytes_read = input_file.gcount();
        
        if (bytes_read > 0) {
            // Простое XOR шифрование (для теста)
            cipher.encrypt_block(buffer, encrypted, bytes_read);
            output_file.write(reinterpret_cast<char*>(encrypted), bytes_read);
        }
    }
    
    input_file.close();
    output_file.close();
    
    last_error = "Успешно";
    return 0;
}

// Функция дешифрования
extern "C" DLL_EXPORT int decrypt_file(const char* input_path, const char* output_path, const char* password) {
    // Открываем файлы
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
    
    // Читаем IV
    unsigned char iv[16];
    input_file.read(reinterpret_cast<char*>(iv), 16);
    
    // Читаем размер оригинального файла
    std::streamsize original_size;
    input_file.read(reinterpret_cast<char*>(&original_size), sizeof(original_size));
    
    // Генерируем ключ
    unsigned char key[32];
    derive_key_from_password(password, key, 32);
    
    // Создаем шифр
    SimpleXOR cipher(key);
    
    // Буфер для чтения
    const size_t BUFFER_SIZE = 4096;
    unsigned char buffer[BUFFER_SIZE];
    unsigned char decrypted[BUFFER_SIZE];
    
    std::streamsize total_written = 0;
    
    // Дешифруем и записываем
    while (input_file.good() && total_written < original_size) {
        input_file.read(reinterpret_cast<char*>(buffer), BUFFER_SIZE);
        std::streamsize bytes_read = input_file.gcount();
        
        if (bytes_read > 0) {
            // Не записываем больше оригинального размера
            std::streamsize to_write = bytes_read;
            if (total_written + to_write > original_size) {
                to_write = original_size - total_written;
            }
            
            // Простое XOR дешифрование
            cipher.decrypt_block(buffer, decrypted, to_write);
            output_file.write(reinterpret_cast<char*>(decrypted), to_write);
            total_written += to_write;
        }
    }
    
    input_file.close();
    output_file.close();
    
    last_error = "Успешно";
    return 0;
}

// Получение ошибки
extern "C" DLL_EXPORT const char* get_last_error() {
    strncpy(error_buffer, last_error.c_str(), sizeof(error_buffer) - 1);
    error_buffer[sizeof(error_buffer) - 1] = '\0';
    return error_buffer;
}