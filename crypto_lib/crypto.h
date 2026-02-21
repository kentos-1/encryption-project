#ifndef CRYPTO_H
#define CRYPTO_H

#ifdef _WIN32
    #ifdef BUILDING_DLL
        #define DLL_EXPORT __declspec(dllexport)
    #else
        #define DLL_EXPORT __declspec(dllimport)
    #endif
#else
    #define DLL_EXPORT __attribute__((visibility("default")))
#endif

extern "C" {
    /**
     * Шифрует файл с использованием AES-256 в режиме CBC
     * 
     * @param input_path Путь к исходному файлу
     * @param output_path Путь для сохранения зашифрованного файла
     * @param password Пароль для шифрования
     * @return 0 в случае успеха, код ошибки в противном случае
     */
    DLL_EXPORT int encrypt_file(const char* input_path, const char* output_path, const char* password);
    
    /**
     * Дешифрует файл, зашифрованный функцией encrypt_file
     * 
     * @param input_path Путь к зашифрованному файлу
     * @param output_path Путь для сохранения расшифрованного файла
     * @param password Пароль для дешифрования
     * @return 0 в случае успеха, код ошибки в противном случае
     */
    DLL_EXPORT int decrypt_file(const char* input_path, const char* output_path, const char* password);
    
    /**
     * Возвращает строку с описанием последней ошибки
     * 
     * @return Строка с описанием ошибки
     */
    DLL_EXPORT const char* get_last_error();
}

#endif // CRYPTO_H