#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
GUI приложение для шифрования/дешифрования файлов
Использует C++ библиотеку для криптографических операций
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import ctypes
import ctypes.util
import os
import sys
import threading
from pathlib import Path

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Криптографический инструмент v1.0")
        self.root.geometry("685x475")
        self.root.resizable(False, False)
        
        # Загружаем C++ библиотеку
        self.crypto_lib = self.load_crypto_library()
        if self.crypto_lib is None:
            messagebox.showerror("Ошибка", 
                                "Не удалось загрузить криптографическую библиотеку!\n"
                                "Убедитесь, что файл crypto.dll (или libcrypto.so) находится в папке с программой.")
            sys.exit(1)
        
        # Настраиваем типы аргументов для функций из библиотеки
        self.setup_ctypes_functions()
        
        # Переменные для хранения путей
        self.input_file_path = tk.StringVar()
        self.output_file_path = tk.StringVar()
        
        # Создаем интерфейс
        self.create_widgets()
        
    def load_crypto_library(self):
        """
        Загружает C++ библиотеку в зависимости от ОС
        """
        system = sys.platform
        
        try:
            if system == "win32":
                # Windows
                lib_path = os.path.join(os.path.dirname(__file__), "crypto.dll")
                return ctypes.CDLL(lib_path)
            elif system == "linux":
                # Linux
                lib_path = os.path.join(os.path.dirname(__file__), "libcrypto.so")
                return ctypes.CDLL(lib_path)
            elif system == "darwin":
                # MacOS
                lib_path = os.path.join(os.path.dirname(__file__), "libcrypto.dylib")
                return ctypes.CDLL(lib_path)
            else:
                return None
        except Exception as e:
            print(f"Ошибка загрузки библиотеки: {e}")
            return None
    
    def setup_ctypes_functions(self):
        """
        Настраивает типы аргументов для функций из C++ библиотеки
        """
        # Функция encrypt_file(const char* input_path, const char* output_path, const char* password)
        self.crypto_lib.encrypt_file.argtypes = [
            ctypes.c_char_p,  # input_path
            ctypes.c_char_p,  # output_path
            ctypes.c_char_p   # password
        ]
        self.crypto_lib.encrypt_file.restype = ctypes.c_int
        
        # Функция decrypt_file(const char* input_path, const char* output_path, const char* password)
        self.crypto_lib.decrypt_file.argtypes = [
            ctypes.c_char_p,  # input_path
            ctypes.c_char_p,  # output_path
            ctypes.c_char_p   # password
        ]
        self.crypto_lib.decrypt_file.restype = ctypes.c_int
        
        # Функция get_last_error() - возвращает строку с последней ошибкой
        self.crypto_lib.get_last_error.argtypes = []
        self.crypto_lib.get_last_error.restype = ctypes.c_char_p
    
    def create_widgets(self):
        """
        Создает все элементы интерфейса
        """
        # Главный фрейм с отступами
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Заголовок
        title_label = ttk.Label(main_frame, text="Шифрование и дешифрование файлов", 
                                font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # === Секция выбора файла ===
        file_frame = ttk.LabelFrame(main_frame, text="Выбор файла", padding="10")
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        file_frame.columnconfigure(1, weight=1)
        
        ttk.Label(file_frame, text="Файл:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        
        self.file_entry = ttk.Entry(file_frame, textvariable=self.input_file_path, width=50)
        self.file_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        
        ttk.Button(file_frame, text="Обзор...", command=self.select_file).grid(row=0, column=2)
        
        # === Секция пароля ===
        password_frame = ttk.LabelFrame(main_frame, text="Пароль", padding="10")
        password_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        password_frame.columnconfigure(1, weight=1)
        
        ttk.Label(password_frame, text="Пароль:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        
        self.password_entry = ttk.Entry(password_frame, width=50, show="•")
        self.password_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), padx=(0, 5))
        
        # Чекбокс для показа пароля
        self.show_password = tk.BooleanVar()
        ttk.Checkbutton(password_frame, text="Показать пароль", 
                       variable=self.show_password, 
                       command=self.toggle_password_visibility).grid(row=1, column=1, sticky=tk.W, pady=(5, 0))
        
        # Индикатор сложности пароля
        self.password_strength = ttk.Progressbar(password_frame, length=200, mode='determinate')
        self.password_strength.grid(row=2, column=1, sticky=tk.W, pady=(5, 0))
        
        # Привязываем проверку пароля к вводу
        self.password_entry.bind('<KeyRelease>', self.check_password_strength)
        
        # === Секция действий ===
        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=3, pady=(0, 10))
        
        self.encrypt_btn = ttk.Button(action_frame, text="🔒 Зашифровать", 
                                      command=self.start_encrypt, width=20)
        self.encrypt_btn.grid(row=0, column=0, padx=5)
        
        self.decrypt_btn = ttk.Button(action_frame, text="🔓 Расшифровать", 
                                      command=self.start_decrypt, width=20)
        self.decrypt_btn.grid(row=0, column=1, padx=5)
        
        # === Индикатор прогресса ===
        progress_frame = ttk.Frame(main_frame)
        progress_frame.grid(row=4, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=(0, 10))
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress.grid(row=0, column=0, sticky=(tk.W, tk.E))
        
        self.status_label = ttk.Label(progress_frame, text="Готов к работе", foreground="gray")
        self.status_label.grid(row=1, column=0, pady=(5, 0))
        
        # === Информационная панель ===
        info_frame = ttk.LabelFrame(main_frame, text="Информация", padding="10")
        info_frame.grid(row=5, column=0, columnspan=3, sticky=(tk.W, tk.E))
        info_frame.columnconfigure(1, weight=1)
        
        ttk.Label(info_frame, text="Алгоритм:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        ttk.Label(info_frame, text="AES-256 (CBC режим)").grid(row=0, column=1, sticky=tk.W)
        
        ttk.Label(info_frame, text="Размер файла:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.file_size_label = ttk.Label(info_frame, text="Не выбран")
        self.file_size_label.grid(row=1, column=1, sticky=tk.W)
        
        # Привязываем обновление информации о файле
        self.input_file_path.trace_add('write', self.update_file_info)
    
    def toggle_password_visibility(self):
        """
        Переключает видимость пароля
        """
        if self.show_password.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="•")
    
    def check_password_strength(self, event=None):
        """
        Проверяет сложность пароля
        """
        password = self.password_entry.get()
        strength = 0
        
        if len(password) >= 8:
            strength += 25
        if any(c.isupper() for c in password):
            strength += 25
        if any(c.islower() for c in password):
            strength += 25
        if any(c.isdigit() for c in password):
            strength += 15
        if any(not c.isalnum() for c in password):
            strength += 10
        
        self.password_strength['value'] = min(strength, 100)
        
        # Меняем цвет в зависимости от сложности
        if strength < 50:
            self.password_strength['style'] = 'red.Horizontal.TProgressbar'
        elif strength < 75:
            self.password_strength['style'] = 'yellow.Horizontal.TProgressbar'
        else:
            self.password_strength['style'] = 'green.Horizontal.TProgressbar'
    
    def select_file(self):
        """
        Открывает диалог выбора файла
        """
        filename = filedialog.askopenfilename(
            title="Выберите файл для шифрования/дешифрования"
        )
        if filename:
            self.input_file_path.set(filename)
    
    def update_file_info(self, *args):
        """
        Обновляет информацию о выбранном файле
        """
        filepath = self.input_file_path.get()
        if filepath and os.path.exists(filepath):
            size = os.path.getsize(filepath)
            # Форматируем размер
            for unit in ['Б', 'КБ', 'МБ', 'ГБ']:
                if size < 1024.0:
                    self.file_size_label.config(text=f"{size:.2f} {unit}")
                    break
                size /= 1024.0
        else:
            self.file_size_label.config(text="Не выбран")
    
    def start_encrypt(self):
        """
        Запускает процесс шифрования в отдельном потоке
        """
        self.start_operation("encrypt")
    
    def start_decrypt(self):
        """
        Запускает процесс дешифрования в отдельном потоке
        """
        self.start_operation("decrypt")
    
    def start_operation(self, operation):
        """
        Запускает операцию (шифрование/дешифрование) в отдельном потоке
        """
        # Проверяем входные данные
        if not self.input_file_path.get():
            messagebox.showerror("Ошибка", "Выберите файл для обработки")
            return
        
        if not self.password_entry.get():
            messagebox.showerror("Ошибка", "Введите пароль")
            return
        
        # Генерируем имя выходного файла
        input_path = self.input_file_path.get()
        if operation == "encrypt":
            output_path = input_path + ".enc"
        else:
            # Для дешифровки убираем .enc если есть
            if input_path.endswith('.enc'):
                output_path = input_path[:-4]
            else:
                output_path = input_path + ".dec"
        
        # Блокируем кнопки во время операции
        self.encrypt_btn.config(state='disabled')
        self.decrypt_btn.config(state='disabled')
        
        # Запускаем прогресс-бар
        self.progress.start(10)
        self.status_label.config(text="Выполняется операция...", foreground="blue")
        
        # Запускаем операцию в отдельном потоке
        thread = threading.Thread(
            target=self.perform_operation,
            args=(operation, input_path, output_path, self.password_entry.get())
        )
        thread.daemon = True
        thread.start()
    
    def perform_operation(self, operation, input_path, output_path, password):
        """
        Выполняет операцию шифрования/дешифрования (запускается в отдельном потоке)
        """
        try:
            # Конвертируем строки в байты для C-функций
            input_bytes = input_path.encode('utf-8')
            output_bytes = output_path.encode('utf-8')
            password_bytes = password.encode('utf-8')
            
            # Вызываем соответствующую функцию из C++ библиотеки
            if operation == "encrypt":
                result = self.crypto_lib.encrypt_file(input_bytes, output_bytes, password_bytes)
            else:
                result = self.crypto_lib.decrypt_file(input_bytes, output_bytes, password_bytes)
            
            # Получаем сообщение об ошибке если есть
            error_msg = self.crypto_lib.get_last_error().decode('utf-8')
            
            # Обновляем GUI в главном потоке
            self.root.after(0, self.operation_complete, result, error_msg, output_path)
            
        except Exception as e:
            self.root.after(0, self.operation_complete, -1, str(e), None)
    
    def operation_complete(self, result, error_msg, output_path):
        """
        Обрабатывает завершение операции
        """
        # Останавливаем прогресс-бар
        self.progress.stop()
        
        # Разблокируем кнопки
        self.encrypt_btn.config(state='normal')
        self.decrypt_btn.config(state='normal')
        
        if result == 0:  # Успех
            self.status_label.config(text="Операция успешно завершена!", foreground="green")
            messagebox.showinfo("Успех", 
                               f"Операция выполнена успешно!\n"
                               f"Результат сохранен в:\n{output_path}")
        else:  # Ошибка
            self.status_label.config(text="Ошибка при выполнении операции", foreground="red")
            messagebox.showerror("Ошибка", 
                               f"Не удалось выполнить операцию.\n"
                               f"Код ошибки: {result}\n"
                               f"Описание: {error_msg}")

def main():
    """
    Главная функция запуска приложения
    """
    root = tk.Tk()
    
    # Настройка стилей для прогресс-бара
    style = ttk.Style()
    style.theme_use('clam')
    style.configure("red.Horizontal.TProgressbar", background='red')
    style.configure("yellow.Horizontal.TProgressbar", background='yellow')
    style.configure("green.Horizontal.TProgressbar", background='green')
    
    app = CryptoGUI(root)
    
    # Центрируем окно на экране
    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')
    
    root.mainloop()

if __name__ == "__main__":
    main()