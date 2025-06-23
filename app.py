import tkinter as tk
import tkinter.font
from tkinter import messagebox, ttk
import sqlite3
import hashlib
import random
import re
from collections import Counter
tkfont = tkinter.font

current_user_email = None
main_win = None

#підключення до бази users.db
users_conn = sqlite3.connect("users.db")
users_conn.execute("PRAGMA foreign_keys = ON;")
users_cursor = users_conn.cursor()
users_cursor.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        email    TEXT    UNIQUE NOT NULL,
        password TEXT    NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stats (
        user_id   INTEGER NOT NULL,
        case_code TEXT    NOT NULL,
        correct   INTEGER NOT NULL,
        total     INTEGER NOT NULL,
        PRIMARY KEY(user_id, case_code),
        FOREIGN KEY(user_id) REFERENCES users(id)
    );""")
users_conn.commit()

#успішність користувача
def update_user_stats(case_code, correct, total):
    #id поточного користувача
    users_cursor.execute("SELECT id FROM users WHERE email=?", (current_user_email,))
    row = users_cursor.fetchone()
    if not row:
        return
    user_id = row[0]

    #чи вже є запис для цього відмінка
    users_cursor.execute(
        "SELECT correct, total FROM stats WHERE user_id=? AND case_code=?",
        (user_id, case_code))
    exists = users_cursor.fetchone()

    if exists:
        prev_correct, prev_total = exists
        users_cursor.execute(
            "UPDATE stats SET correct=?, total=? WHERE user_id=? AND case_code=?",
            (prev_correct + correct, prev_total + total, user_id, case_code))
    else:
        users_cursor.execute(
            "INSERT INTO stats (user_id, case_code, correct, total) VALUES (?, ?, ?, ?)",
            (user_id, case_code, correct, total))
    users_conn.commit()


#підключення до основної БД
pol_conn = sqlite3.connect('pol.sqlite3')
pol_cursor = pol_conn.cursor()

def configure_window(win, width, height, resizable=False):
    win.resizable(resizable, resizable)
    screen_w, screen_h = win.winfo_screenwidth(), win.winfo_screenheight()
    x = (screen_w - width)//2
    y = (screen_h - height)//2
    win.geometry(f"{width}x{height}+{x}+{y}")

#хешування паролю
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

#валідація пошти
def validate_email(email):
    regex = r'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$'
    return re.match(regex, email)

#авторизація
def login_user(email, password):
    hashed = hash_password(password)
    users_cursor.execute("SELECT * FROM users WHERE email=? AND password=?", (email, hashed))
    return users_cursor.fetchone()

#реєстрація
def register_user(email, password):
    try:
        hashed = hash_password(password)
        users_cursor.execute(
            "INSERT INTO users (email, password) VALUES (?, ?)",
            (email, hashed))
        users_conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False

#перевірка email
def check_email_input(entry, error_label):
    email = entry.get()
    if not validate_email(email):
        error_label.config(text="Невірний формат електронної пошти", fg="red")
    else:
        error_label.config(text="", fg="red")

#очищення фрейма
def clear_frame(frame):
    for widget in frame.winfo_children():
        widget.destroy()

#повернення на стартовий екран
def back_to_selection():
    global login_frame, register_frame, selection_frame

    if 'login_frame' in globals() and login_frame is not None and login_frame.winfo_exists():
        login_frame.pack_forget()
    if 'register_frame' in globals() and register_frame is not None and register_frame.winfo_exists():
        register_frame.pack_forget()

    if 'selection_frame' in globals() and selection_frame is not None and selection_frame.winfo_exists():
        if not selection_frame.winfo_ismapped():
            selection_frame.pack(expand=True, fill=tk.BOTH)
    else:  #якщо раптом selection_frame немає, створюємо його
        print("selection_frame не знайдено. Створюю його заново.")
        create_selection_frame_content(root)
        if 'selection_frame' in globals() and selection_frame is not None:
            selection_frame.pack(expand=True, fill=tk.BOTH)

#форма входу
def open_login_window():
    global login_frame
    if selection_frame.winfo_exists():
        selection_frame.pack_forget()
    if register_frame.winfo_exists():
        clear_frame(register_frame)
        register_frame.pack_forget()

    #форма логіну
    clear_frame(login_frame)

    tk.Label(login_frame, text="Електронна пошта", font=("Montserrat", 16), bg="#f4f6f8").pack(pady=(50, 5))
    email_entry = tk.Entry(login_frame, width=30, font=("Montserrat", 12))
    email_entry.pack(pady=(0, 0))
    email_error_label = tk.Label(login_frame, text="", font=("Montserrat", 10), bg="#f4f6f8", fg="red")
    email_error_label.pack()

    tk.Label(login_frame, text="Пароль", font=("Montserrat", 16), bg="#f4f6f8").pack(pady=(0, 5))
    password_entry = tk.Entry(login_frame, show="*", width=30, font=("Montserrat", 12))
    password_entry.pack(pady=(0, 30))

    email_entry.bind("<FocusOut>", lambda event: check_email_input(email_entry, email_error_label))

    def login_action():
        email = email_entry.get()
        password = password_entry.get()

        if not email or not password:
            messagebox.showerror("Помилка", "Пошта та пароль не можуть бути порожніми", parent=login_frame)
            return
        if not validate_email(email):
            messagebox.showerror("Помилка", "Введено некоректну електронну пошту", parent=login_frame)
            return

        user = login_user(email, password)
        if user:
            login_frame.pack_forget()
            open_main_window(email)
        else:
            messagebox.showerror("Помилка", "Невірний email або пароль", parent=login_frame)

    tk.Button(login_frame, text="Увійти", command=login_action, width=10, height=1,
              bg="#A3EEFF", fg="black", font=("Montserrat", 14)) \
        .pack(pady=(0, 10))
    tk.Button(login_frame, text="Назад", command=back_to_selection, width=12, height=1,
              bg="#E0E0E0", fg="black", font=("Montserrat", 12)) \
        .pack(pady=(0, 50))

    login_frame.pack(expand=True, fill=tk.BOTH)


#форма реєстрації
def open_register_window():
    global register_frame

    if selection_frame.winfo_exists(): selection_frame.pack_forget()
    if login_frame.winfo_exists():
        clear_frame(login_frame)  # Очищаємо вміст перед pack_forget
        login_frame.pack_forget()

    clear_frame(register_frame)

    tk.Label(register_frame, text="Електронна пошта", font=("Montserrat", 16), bg="#f4f6f8") \
        .pack(pady=(50, 5))
    email_entry_reg = tk.Entry(register_frame, width=30, font=("Montserrat", 12))
    email_entry_reg.pack(pady=(0, 0))

    email_error_label_reg = tk.Label(register_frame, text="", font=("Montserrat", 10), bg="#f4f6f8", fg="red")
    email_error_label_reg.pack()

    tk.Label(register_frame, text="Пароль", font=("Montserrat", 16), bg="#f4f6f8") \
        .pack(pady=(0, 5))
    password_entry_reg = tk.Entry(register_frame, show="*", width=30, font=("Montserrat", 12))
    password_entry_reg.pack(pady=(0, 10))

    tk.Label(register_frame, text="Підтвердіть пароль", font=("Montserrat", 16), bg="#f4f6f8") \
        .pack(pady=(10, 5))
    confirm_password_entry_reg = tk.Entry(register_frame, show="*", width=30, font=("Montserrat", 12))
    confirm_password_entry_reg.pack(pady=(0, 30))

    email_entry_reg.bind("<FocusOut>", lambda event: check_email_input(email_entry_reg, email_error_label_reg))

    def register_action():
        email = email_entry_reg.get()
        password = password_entry_reg.get()
        confirm_password = confirm_password_entry_reg.get()

        if not email or not password or not confirm_password:
            messagebox.showerror("Помилка", "Всі поля мають бути заповнені", parent=register_frame)
            return
        if not validate_email(email):
            messagebox.showerror("Помилка", "Введено некоректну електронну пошту", parent=register_frame)
            return
        if password != confirm_password:
            messagebox.showerror("Помилка", "Паролі не співпадають", parent=register_frame)
            return
        if len(password) < 6:
            messagebox.showerror("Помилка", "Пароль має бути не менше 6 символів", parent=register_frame)
            return

        if register_user(email, password):
            messagebox.showinfo("Успішно", "Користувача зареєстровано!", parent=register_frame)
            back_to_selection()
        else:
            messagebox.showerror("Помилка", "Ця електронна пошта вже використовується", parent=register_frame)

    tk.Button(register_frame, text="Зареєструватися", command=register_action,
              width=14, height=1, bg="#C3E7EF", fg="black", font=("Montserrat", 14)) \
        .pack(pady=(0, 10))
    tk.Button(register_frame, text="Назад", command=back_to_selection,
              width=12, height=1, bg="#E0E0E0", fg="black", font=("Montserrat", 12)) \
        .pack(pady=(0, 50))

    register_frame.pack(expand=True, fill=tk.BOTH)

#Обробник закриття/виходу для main_win
def _on_main_win_close_handler():
    global main_win, current_user_email
    configure_window(main_win, 1000, 800)

    if main_win and main_win.winfo_exists():
        try:
            main_win.grab_release()
        except tk.TclError:
            pass
        main_win.destroy()
    main_win = None
    current_user_email = None  #скидаємо поточного користувача

    if root.winfo_exists():
        root.deiconify()
    back_to_selection()

#обрахунок успішності
def show_user_stats():
    global main_win, current_user_email
    configure_window(main_win, 400, 400)
    clear_frame(main_win)
    main_win.configure(bg="#f4f6f8")

    tk.Button(
        main_win,
        text="← Назад", command=lambda: open_main_window(current_user_email),
        width=12, height=1, bg="#E0E0E0", fg="black", font=("Montserrat", 12)).pack(anchor='nw', pady=10, padx=10)

    tk.Label(
        main_win,
        text="Моя успішність",
        font=("Montserrat", 16, "bold"), bg="#f4f6f8").pack(pady=(0,20))

    #завантажуємо статистику з БД
    users_cursor.execute("SELECT id FROM users WHERE email=?", (current_user_email,))
    user_id = users_cursor.fetchone()[0]
    users_cursor.execute("SELECT case_code, correct, total FROM stats WHERE user_id=?", (user_id,))
    rows = users_cursor.fetchall()
    stats = {code: (c, t) for code,c,t in rows}

    #використовуємо PLAIN_CASE для назв
    for code, name in PLAIN_CASE.items():
        record = stats.get(code)
        if record:
            c, t = record
            pct = int(round(c * 100 / t)) if t else 0
            text = f"{name.capitalize()}: {pct}% ({c}/{t})"
        else:
            text = f"{name.capitalize()}: Немає даних"
        tk.Label(
            main_win,
            text=text, font=("Montserrat", 12), bg="#f4f6f8", anchor="w").pack(fill="x", padx=20, pady=5)


#основне вікно після входу
def open_main_window(email_param):
    global main_win, current_user_email
    current_user_email = email_param

    if main_win is None or not main_win.winfo_exists():
        main_win = tk.Toplevel(root)
        main_win.title("Основне меню")
        main_win.protocol("WM_DELETE_WINDOW", _on_main_win_close_handler)

    main_win.geometry("400x550")
    configure_window(main_win, 400, 550)
    main_win.configure(bg="#f4f6f8")

    clear_frame(main_win)

    container = tk.Frame(main_win, bg="#f4f6f8")
    container.place(relx=0.5, rely=0.5, anchor="center")

    tk.Label(
        container,
        text=f"Вітаємо, {current_user_email}!",
        font=("Montserrat", 14, "bold"),
        bg="#f4f6f8"
    ).pack(pady=(0, 20))

    #кнопки меню
    btn_cfg = dict(width=25, height=2, fg="black", font=("Montserrat", 12))
    tk.Button(
        container, text="Теоретичні матеріали",
        command=show_theoretical_materials,
        bg="#A3EEFF", **btn_cfg).pack(pady=5)
    tk.Button(
        container, text="Тестування",
        command=show_testing,
        bg="#90E0F0", **btn_cfg).pack(pady=5)
    tk.Button(
        container, text="Про додаток",
        command=show_about_app,
        bg="#C2F4FF", **btn_cfg).pack(pady=5)

    tk.Button(
        container, text="Моя успішність",
        command=show_user_stats,
        bg="#B4F8C8", **btn_cfg).pack(pady=5)

    #кнопка виходу
    tk.Button(
        container, text="Вийти",
        command=_on_main_win_close_handler,
        width=12, height=1,
        bg="#E0E0E0", fg="black", font=("Montserrat", 12)).pack(pady=(20, 0))

    if root.winfo_ismapped():
        root.withdraw()

    main_win.deiconify()
    main_win.lift()
    main_win.focus_set()
    try:
        main_win.grab_set()
    except tk.TclError:
        pass

bold_font = None
normal_font = None

#теоретичний матеріал
def show_theoretical_materials():
    global main_win, bold_font, normal_font, current_user_email
    if main_win is None or not main_win.winfo_exists():
        return
    configure_window(main_win, 1000, 800)
    main_win.resizable(True, True)

    clear_frame(main_win)
    main_win.configure(bg="#f0f8ff")

    if bold_font is None:
        bold_font = tkfont.Font(family="Montserrat", size=12, weight="bold")
    if normal_font is None:
        normal_font = tkfont.Font(family="Montserrat", size=12)

    tk.Button(main_win,
              text="← Назад",
              command=lambda: open_main_window(current_user_email),
              width=12, height=1,
              bg="#E0E0E0", fg="black",
              font=("Montserrat", 12)) \
      .pack(anchor="nw", pady=10, padx=10)

    tk.Label(main_win,
             text="Теоретичні матеріали",
             font=("Montserrat", 16, "bold"),
             bg="#f0f8ff",
             justify="center") \
      .pack(fill="x", pady=(0, 15))


    #вид та навігація
    content_frame = tk.Frame(main_win, bg="#f0f8ff")
    content_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))

    nav_frame = tk.Frame(content_frame, width=200, bg="#E5F5F8", padx=10, pady=10)
    nav_frame.pack(side="left", fill="y", padx=(0,10))
    nav_frame.pack_propagate(False)

    tk.Label(nav_frame,
             text="Розділи",
             font=("Montserrat", 14, "bold"),
             bg="#E5F5F8") \
      .pack(fill="x", pady=(0,10))

    #Права область
    text_frame = tk.Frame(content_frame, bg="#f0f8ff")
    text_frame.pack(side="left", fill="both", expand=True)
    canvas = tk.Canvas(text_frame, bg="#f0f8ff", highlightthickness=0)
    vsb = tk.Scrollbar(text_frame, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    #внутрішній фрейм
    inner = tk.Frame(canvas, bg="#f0f8ff", padx=10, pady=10)
    window_id = canvas.create_window((0, 0), window=inner, anchor="nw")

    # Єдина функція-послухач, яка і розвертає inner по ширині, і оновлює wraplength
    def _on_canvas_configure(event):
        canvas.itemconfig(window_id, width=event.width)        #розтягнути inner по всій ширині canvas
        canvas.configure(scrollregion=canvas.bbox("all"))        #область прокрутки
        _update_wrap_labels_in_inner(event.width)        #оновити wraplength для лейблів

    canvas.bind('<Configure>', _on_canvas_configure)

    def _update_wrap_labels_in_inner(canvas_width):
        if canvas_width <= 1:
            return

        #Відступи
        base_wraplength = canvas_width - (2 * 10) - (2 * 20)
        if base_wraplength < 150:
            base_wraplength = 150

        list_item_wraplength = canvas_width - (2 * 10) - (2 * 20) - (2 * 20)
        if list_item_wraplength < 100:
            list_item_wraplength = 100

        sub_list_item_wraplength = canvas_width - (2 * 10) - (2 * 20) - (2 * 20) - (2 * 20)
        if sub_list_item_wraplength < 80:
            sub_list_item_wraplength = 80

        for widget in inner.winfo_children():
            if isinstance(widget, tk.Label) and not hasattr(widget, "_no_auto_wrap") and widget.master == inner:
                widget.config(wraplength=base_wraplength)

            elif isinstance(widget, tk.Frame) and hasattr(widget, "_is_list_frame_outer"):
                for child in widget.winfo_children():
                    if isinstance(child, tk.Label) and not hasattr(child, "_no_auto_wrap"):
                        child.config(wraplength=list_item_wraplength)
                    # вкладені списки
                    elif isinstance(child, tk.Frame) and hasattr(child, "_is_sub_list_frame"):
                        for sub_child in child.winfo_children():
                            if isinstance(sub_child, tk.Label) and not hasattr(sub_child, "_no_auto_wrap"):
                                sub_child.config(wraplength=sub_list_item_wraplength)

        inner.update_idletasks()
        canvas.configure(scrollregion=canvas.bbox("all"))

    def update_line_frame_label_wraplength(event, bold_l_widget, normal_l_widget):
        line_frame_actual_width = event.width
        if line_frame_actual_width <= 1: return

        bold_exists = bold_l_widget and bold_l_widget.winfo_exists()
        normal_exists = normal_l_widget and normal_l_widget.winfo_exists()

        if not bold_exists and not normal_exists: return
        if (normal_l_widget and not normal_exists) or \
                (bold_l_widget and not bold_exists and normal_l_widget is not None): return

        bold_l_width = 0
        if bold_exists:
            bold_l_width = bold_l_widget.winfo_reqwidth()

        available_for_normal = line_frame_actual_width - bold_l_width - 5

        if normal_exists:
            normal_l_widget.config(wraplength=max(50, available_for_normal))
        elif bold_exists:
            bold_l_widget.config(wraplength=max(50, line_frame_actual_width - 5))

    def show_content(title_text, content):
        for widget in inner.winfo_children():
            widget.destroy()

        page_title_label = tk.Label(inner, text=title_text, font=("Montserrat", 14, "bold"), bg="#f0f8ff", anchor="w",
                                    pady=10)
        page_title_label.pack(fill="x")
        page_title_label._no_auto_wrap = True  #заголовки не переносимо автоматично

        for item in content:
            if isinstance(item, str) and item.strip():
                label = tk.Label(inner, text=item, font=normal_font, bg="#f0f8ff", justify="left", anchor="w", pady=2)
                label.pack(fill="x", padx=20)  #загальний відступ для текстових блоків

            elif isinstance(item, dict) and "відмінки" in item and title_text == "Іменник":
                cases_data = item["відмінки"]
                table_frame = tk.Frame(inner, bg="#f0f8ff", pady=10)
                table_frame.pack(pady=5, padx=20, anchor="center")
                col_widths = [0, 0]
                label_internal_padx = 10
                header1_text = "Відмінок"
                header2_text = "Питання"
                col_widths[0] = bold_font.measure(header1_text) + 2 * label_internal_padx
                col_widths[1] = bold_font.measure(header2_text) + 2 * label_internal_padx
                for case_text, question_text in cases_data.items():
                    col_widths[0] = max(col_widths[0], normal_font.measure(case_text) + 2 * label_internal_padx)
                    col_widths[1] = max(col_widths[1], normal_font.measure(question_text) + 2 * label_internal_padx)

                for i_col in range(2):
                    table_frame.grid_columnconfigure(i_col, minsize=col_widths[i_col], weight=1)

                h1_label = tk.Label(table_frame, text=header1_text, font=bold_font, bg="#e8f5e9", borderwidth=1,
                                    relief="solid", padx=label_internal_padx, pady=5, height=2, anchor="center",
                                    justify=tk.CENTER)
                h1_label.grid(row=0, column=0, padx=1, pady=1, sticky="nsew")
                h2_label = tk.Label(table_frame, text=header2_text, font=bold_font, bg="#e8f5e9", borderwidth=1,
                                    relief="solid", padx=label_internal_padx, pady=5, height=2, anchor="center",
                                    justify=tk.CENTER)
                h2_label.grid(row=0, column=1, padx=1, pady=1, sticky="nsew")

                h1_label.config(wraplength=max(10, col_widths[0] - 2 * label_internal_padx))
                h2_label.config(wraplength=max(10, col_widths[1] - 2 * label_internal_padx))

                row_idx = 1
                for case_text, question_text in cases_data.items():
                    c_label = tk.Label(table_frame, text=case_text, font=normal_font, bg="#f0f8ff", borderwidth=1,
                                       relief="solid", padx=label_internal_padx, pady=5, height=3, anchor="center",
                                       justify=tk.CENTER, wraplength=max(10, col_widths[0] - 2 * label_internal_padx))
                    c_label.grid(row=row_idx, column=0, padx=1, pady=1, sticky="nsew")
                    q_label = tk.Label(table_frame, text=question_text, font=normal_font, bg="#f0f8ff", borderwidth=1,
                                       relief="solid", padx=label_internal_padx, pady=5, height=3, anchor="center",
                                       justify=tk.CENTER, wraplength=max(10, col_widths[1] - 2 * label_internal_padx))
                    q_label.grid(row=row_idx, column=1, padx=1, pady=1, sticky="nsew")
                    row_idx += 1

            elif isinstance(item, dict):
                for bold_text, normal_text_content in item.items():
                    line_frame = tk.Frame(inner, bg="#f0f8ff")
                    line_frame.pack(fill="x", padx=20)

                    bold_label = tk.Label(line_frame, text=bold_text, font=bold_font, bg="#f0f8ff", justify="left",
                                          anchor="w", pady=0)
                    bold_label.pack(side="left", pady=(1, 1))

                    normal_label = None
                    if normal_text_content and normal_text_content.strip():
                        normal_label = tk.Label(line_frame, text=" " + normal_text_content, font=normal_font,
                                                bg="#f0f8ff", justify="left", anchor="w", pady=0)
                        normal_label.pack(side="left", fill="x", expand=True, pady=(1, 1))

                    line_frame.bind("<Configure>",
                                    lambda event, bl=bold_label, nl=normal_label: update_line_frame_label_wraplength(
                                        event, bl, nl))

            elif isinstance(item, tuple) and len(item) == 2:
                type_or_header, data = item

                if type_or_header == "" and data is None:
                    spacer_label = tk.Label(inner, text="", font=normal_font, bg="#f0f8ff", pady=3)
                    spacer_label.pack(fill="x")
                    spacer_label._no_auto_wrap = True

                elif type_or_header in ["bullet", "numbered"] and isinstance(data, list):
                    list_type = type_or_header
                    outer_list_items = data

                    list_frame_outer = tk.Frame(inner, bg="#f0f8ff")
                    list_frame_outer.pack(fill="x", padx=20)
                    list_frame_outer._is_list_frame_outer = True

                    for i_enum, point_data in enumerate(outer_list_items, 1):
                        prefix = f"{i_enum}. " if list_type == "numbered" else "• "

                        if isinstance(point_data, str):
                            # Простий пункт списку. Відступ padx=20 відносно list_frame_outer
                            point_label = tk.Label(list_frame_outer, text=f"{prefix}{point_data}", font=normal_font,
                                                   bg="#f0f8ff", justify="left", anchor="w", pady=1)
                            point_label.pack(fill="x", padx=20)

                        elif isinstance(point_data, tuple) and len(point_data) == 2 and \
                                isinstance(point_data[0], str) and isinstance(point_data[1], tuple) and \
                                len(point_data[1]) == 2 and point_data[1][0] == "bullet" and \
                                isinstance(point_data[1][1], list):

                            main_rule_text = point_data[0]
                            sub_bullet_items = point_data[1][1]

                            #основний текст нумерований
                            rule_label = tk.Label(list_frame_outer, text=f"{prefix}{main_rule_text}", font=normal_font,
                                                  bg="#f0f8ff", justify="left", anchor="w", pady=1)
                            rule_label.pack(fill="x", padx=20)

                            #вкладені марковані підпункти
                            sub_list_frame = tk.Frame(list_frame_outer, bg="#f0f8ff")
                            sub_list_frame.pack(fill="x", padx=20)
                            sub_list_frame._is_sub_list_frame = True  # Позначка

                            for sub_item_text in sub_bullet_items:
                                sub_label = tk.Label(sub_list_frame, text=f"• {sub_item_text}", font=normal_font,
                                                     bg="#f0f8ff", justify="left", anchor="w", pady=1)
                                sub_label.pack(fill="x", padx=20)
                        else:
                            # Непідтримуваний формат елемента списку
                            print(f"Warning: Unsupported list item format: {point_data}")

            elif isinstance(item, list) and all(isinstance(sub_item, list) for sub_item in item):
                if not item: continue
                table_frame = tk.Frame(inner, bg="#f0f8ff", pady=10)
                table_frame.pack(pady=5, padx=20, anchor="center")
                num_cols = len(item[0])
                col_widths = [0] * num_cols
                label_internal_padx = 5
                for r_idx, row_data_list in enumerate(item):
                    for c_idx, cell_val in enumerate(row_data_list):
                        current_font_for_measure = bold_font if r_idx == 0 else normal_font
                        col_widths[c_idx] = max(col_widths[c_idx], current_font_for_measure.measure(
                            str(cell_val)) + 2 * label_internal_padx)

                for c_idx in range(num_cols):
                    table_frame.grid_columnconfigure(c_idx, minsize=col_widths[c_idx], weight=1)

                for r_idx, row_data_list in enumerate(item):
                    for c_idx, cell_val in enumerate(row_data_list):
                        is_header = (r_idx == 0)
                        current_font_style = bold_font if is_header else normal_font
                        cell_bg = "#e8f5e9" if is_header else "#f0f8ff"
                        cell_height = 2 if is_header else 3
                        cell_wraplength = max(10, col_widths[c_idx] - 2 * label_internal_padx)

                        label = tk.Label(table_frame, text=str(cell_val), font=current_font_style, bg=cell_bg,
                                         borderwidth=1, relief="solid", padx=label_internal_padx, pady=5,
                                         height=cell_height, anchor="center", justify=tk.CENTER,
                                         wraplength=cell_wraplength)
                        label.grid(row=r_idx, column=c_idx, padx=1, pady=1, sticky="nsew")

        inner.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))
        _update_wrap_labels_in_inner(canvas.winfo_width())

    theory_content = {
        "Іменник": [
            "Іменник (пол. rzeczownik) — це одна з головних частин мови в польській, що позначає предмети, явища, осіб, тварин, а також статуси, професії тощо. У польській мові іменники належать до змінюваних частин мови. Вони змінюються за відмінками (пол. przypadki), що називається відмінюванням (пол. deklinacja). Важливо не плутати із дієвідмінюванням (пол. koniugacja), що стосується дієслів.",
            "І польська, і українська мови мають спільну систему відмінків та подібні питання до них. У польській налічується сім відмінків:",
            {"відмінки": {
                "Mianownik (укр. називний відмінок)": "kto? co? (хто? що?)",
                "Dopełniacz (укр. родовий відмінок)": "kogo? czego? (кого? чого?)",
                "Celownik (укр. давальний відмінок)": "komu? czemu? (кому? чому?)",
                "Biernik (укр. знахідний відмінок)": "kogo? co? (кого? що?)",
                "Narzędnik (укр. орудний відмінок)": "kim? czym? (ким? чим?)",
                "Miejscownik (укр. місцевий відмінок)": "o kim? o czym? (на кому? на чому?)",
                "Wołacz (укр. кличний відмінок)": "hej!"
            }},
            {"Іменники змінюються за:": ""},
            ("numbered", [
                "Родом (пол. rodzaj): чоловічий (пол. męski), жіночий (пол. żeński) та середній (пол. nijaki).",
                "Категорією істот та неістот (пол. istoty / nieistoty): До категорії істот належать іменники, що позначають людей та живих істот. Натомість до категорії неістот відносяться всі інші іменники — ті, що називають предмети, явища, поняття тощо. Цей поділ особливо важливий для іменників чоловічого роду (пол. rodzaj męski), адже у родовому та знахідному відмінках однини вони можуть мати різні закінчення залежно від того, чи є істотою, чи ні.",
                "Числом (пол. liczba): однина (пол. liczba pojedyncza) та множина (пол. liczba mnoga). Множина має дві окремі форми, залежно від того, хто або що є підметом:"
            ]),
            ("bullet", [
                "Чоловічо-особова форма (пол. форма męskoosobowa) — для груп, що включають щонайменше одного чоловіка.",
                "Нечоловічо-особова форма (пол. форма niemęskoosobowa) — групи жінок, предметів, тварин тощо."
            ]),
            "Як і в українській мові, деякі іменники мають лише форму множини (наприклад, drzwi, okulary).",
            "Також для польської характерне чергування звуків в основі (корені) слова, яке ми розбиратимемо далі.",
        ],

        "Називний відмінок": [

            {"Характерні форми однини:": ""},

            {"Чоловічий рід": ""},
            ("numbered", [
                "Іменники чоловічого роду зазвичай закінчуються на приголосну.",
                "У деяких іменників зустрічається закінчення -a."
            ]),

            {"Жіночий рід": ""},
            ("numbered", [
                "Іменники жіночого роду зазвичай закінчуються на -a.",
                "Деякі іменники мають закінчення -i або закінчуються на приголосну. Приклад: noc."
            ]),

            {"Середній рід": ""},
            ("numbered", [
                "Іменники середнього роду зазвичай закінчуються на -o, -e або -um.",
                "Деякі іменники мають закінчення на -ę. Приклади: imię, cielę."
            ]),
            ("", None),
            ("", None),
            {"Відмінювання у множині називного відмінку:": ""},

            {"Чоловічий рід": ""},
            ("numbered", [
                "Характерним є закінчення -owie для іменників на позначення родинних зв'язків, імен, назв професій, національностей та титулів. Приклад: profesor – profesorowie.",
                "Після твердих приголосних додається -i (крім -k, -g(a), -r). Приклад: blondyn – blondyni.",
                ("Якщо в однині іменник чоловічого роду закінчується на -a, то закінчення опускається, попередній приголосний пом'якшується і відбувається чергування. Приклад: student – studenci.",
                 ("bullet", [
                     "t пом'якшується до ci",
                     "st пом'якшується до ści",
                     "z пом'якшується до zi (ź)"
                 ])
                 ),
                ("Іменники, основи яких закінчуються в однині на -k, -g(a), -r, -iec, приймають закінчення -y і чергуються. Приклад: kolega – koledzy; chłopiec – chłopcy.",
                 ("bullet", [
                     "g змінюється на dz",
                     "k змінюється на c",
                     "r змінюється на rz",
                     "iec змінюється на c"
                 ])
                 ),
                ("Основи в однині на -d, -ch, приймають закінчення -i у множині і відбувається чергування. Приклад: Szwed – Szwedzi; Włoch – Włosi.",
                 ("bullet", [
                     "d змінюється на dz",
                     "ch змінюється на s"
                 ])
                 ),
                "Чоловічо-особові іменники, які закінчуються в однині на шиплячий та м’який приголосний (-c, -cz, -sz, -ść та -l, -rz), приймають закінчення -e. Приклад: gracz – gracze, lekarz – lekarze."
            ]),
            {"Винятки:": "brat – bracia; ksiądz – księża; człowiek – ludzie."},

            {"Жіночий рід": ""},
            "Іменники жіночого роду в множині мають закінчення, аналогічні закінченням нечоловічо-особових іменників.",
            ("numbered", [
                "Якщо в однині іменник має закінчення -a, то у множині змінюється на -i після твердих приголосних k та g. Приклад: apteka – apteki.",
                "Після інших твердих приголосних використовується закінчення -y. Приклад: kobieta – kobiety.",
                "Основи на м'який приголосний або шиплячі (–ń, -sz, -cz, -rz, -ż, -l, -j, -c, -dz, -ś, -ć, -ź) отримують закінчення -e. Приклад: pani – panie; ulica – ulice; pokój – pokoje."
            ]),

            {"Середній рід": ""},
            ("numbered", [
                "Більшість іменників середнього роду в називному відмінку множини отримують закінчення -a. Приклад: drzewo – drzewa; muzeum – musea.",
                "Іменники середнього роду, що закінчуються на -ę в однині, змінюють основу у множині. При закінченні на -mię основа змінюється на -miona. Приклад: imię – imiona; ramię – ramiona.",
                "В інших випадках -ę перетворюється на -ęta. Приклад: dziewczę – dziewczęta."
            ]),
            {"Виняток:": "dziecko – dzieci."}
        ],
        "Родовий відмінок": [
            "Родовий відмінок у польській мові, подібно до української, використовується для вираження різних типів означальних відношень. Зазвичай іменник у родовому відмінку слідує за іншим іменником або групою іменників, до яких він належить або які уточнює. Родовий відмінок вимагають прийменники obok, bez, od, do, z, dla, naprzeciwko. Також деякі дієслова, такі як szukać (укр. шукати), słuchać (укр. слухати), потребують після себе родового відмінка.",
            ("", None),
            {"Іменники в однині формуються наступним чином:": ""},

            {"Чоловічий рід": ""},
            {"Закінчуються на -а:": ""},  # Підзаголовок
            ("numbered", [
                "Всі іменники на позначення назв істот, тобто такі, які позначають людей або тварин. Приклад: kot – kota; lekarz – lekarza.",
                "Іменники, які означають предмет і закінчуються на м’який приголосний (крім тих, що мають у закінченні -j) або на -уk, -іk. Приклад: pień – pnia, koszyk – koszyka.",
                "Місяці, позначення міри і ваги, інструменти, більшість назв польських міст. Приклад: kilogram – kilograma, Kraków – Krakowa; nóż – noża."
            ]),
            {"Закінчуються на -u:": ""},  # Підзаголовок
            ("numbered", [
                "Запозичені іменники. Приклад: hotel – hotelu, klub – klubu.",
                "Назви транспортних засобів. Приклад: tramwaj – tramwaju, rower – roweru.",
                "Дні тижня. Приклад: czwartek – czwartku, poniedziałek – poniedziałku.",
                "Незлічувані іменники. Приклад: miód – miodu, piasek – piasku.",
                "Іменники-неістоти, що не відносяться до категорій попереднього пункту, означають предмети чи абстрактні поняття, а також закінчуються на -j. Приклад: teatr – teatru, Londyn – Londynu, pokój – pokoju."
            ]),
            {"Виняток:": "maj – maja."},  # Жирний "Виняток:" з відступом
            "З вище наведених прикладів бачимо, що в родовому відмінку відбувається чергування голосних:",
            ("bullet", [
                "e зникає",
                "ó чергується на o",
                "ą чергується на ę"
            ]),

            {"Жіночий рід": ""},
            ("numbered", [
                "Закінчення -y вживається після твердого приголосного. Приклад: cisza – ciszy.",
                "Після приголосних l, k, g вживається закінчення -i. Приклад: książka – książki."
            ]),

            {"Середній рід": ""},
            ("numbered", [
                "Якщо іменник закінчується на -o или -e в називному відмінку, то в родовому відмінку він має закінчення -a. Приклад: оkо – оkа.",
                "Іменники із закінченням -ę в називному відмінку, отримують закінчення -іа. Приклад: imię – imienia, kurczę – kurczęcia."
            ]),
            ("", None),
            ("", None),
            {"Розглянемо закінчення множини родового відмінка.": ""},
            {"Чоловічий рід": ""},
            ("numbered", [
                "Більшість іменників закінчуються на -ów. Приклад: sąsiad – sąsiadów.",
                "Після м’якого приголосного вживається -i. Приклад: gość – gości.",
                "Іменники, корінь яких закінчується на cz, ż (rz), sz, dz, l, і деякі іменники, що закінчуються на -c, мають закінчення -y. Приклад: pisarz – pisarzy, tysiąc – tysięcy."
            ]),
            {"Винятки:": "uczeń – uczniów, kraj – krajów."},

            {"Жіночий рід": ""},
            ("numbered", [
                "Іменники жіночого роду, основа яких закінчується на твердий або м’який приголосний та які мають закінчення -а чи -і, зазвичай втрачають закінчення. Приклад: noga – nóg. При збігу двох приголосних між ними з’являється випадне -е-. Приклад: bułka – bułek.",
                "Іменники жіночого роду, які не мають закінчення у називному відмінку однини, у родовому множини набувають закінчення -i. Приклад: pamięć – pamięci."
            ]),

            {"Середній рід": ""},
            ("numbered", [
                "Іменники середнього роду на -е, -о у родовому відмінку множини також втрачають закінчення, а передостання голосна в цих словах може опускатися або змінюватись на іншу. Приклад: zdjęcie - zdjęć, jabłko - jabłek, okno - okien, święto - świąt.",
                "Іменники середнього роду, що закінчуються на -um, в родовому відмінку мають закінчення -ów. Приклад: muzeum - muzeów.",
                "Іменники на -ę в родовому відмінку множини мають такі форми: imię - imion, cielę - cieląt, zwierzę - zwierząt і т.д."
            ]),
        ],
        "Давальний відмінок": [

            "Давального відмінка потребують прийменники ku, dzięki, przeciw. Також з давальним відмінком сполучаються певні дієслова, наприклад, dać, dziękować, pomagać тощо.",
            ("", None),
            {"Для однини характерні закінчення:": ""},
            {"Чоловічий рід": ""},
            ("numbered", [
                "Іменники чоловічого роду в однині у давальному відмінку зазвичай мають закінчення -owi, яке додається до форми називного відмінка. Приклад: syn – synowi.",
                "Однак деякі іменники, переважно односкладові, мають закінчення -u. Приклад: brat – bratu.",
                "Іменники чоловічого роду, що в називному відмінку закінчуються на -a, відмінюються за зразком жіночого роду, що буде описаний далі."
            ]),

            {"Чоловічий та жіночий роди": ""},
            ("numbered", [
                "Іменники чоловічого й жіночого роду на -а з основою на твердий приголосний у давальному відмінку однини мають закінчення -e, при цьому приголосний у кінці основи зазнає пом’якшення. Приклад: kolega – koledze.",
                "Іменники жіночого роду на -а та -і з основою на м’який приголосний у давальному відмінку однини отримують закінчення -і. Приклад: pani – pani, pamięć – pamięci.",
                "Якщо ж основа закінчується на стверділий приголосний, вони мають закінчення -у. Приклад: róża – róży."
            ]),


            {"Середній рід": ""},
            ("numbered", [
                "Іменники в давальному відмінку однини мають закінчення -u. Приклад: oko – oku.",
                "Іменники на -ę мають закінчення -iu. Приклад: imię – imieniu."
            ]),
            ("", None),
            ("", None),
            {"Множина:": ""},
            (
                "Усі іменники в давальному відмінку множини закінчуються на -оm."
            ),
            ("", None),

            "Для давального відмінку також характерне чергування звуків в кореневих частинах:",
            ("bullet", [
                "ch + e = sze (mucha – musze)",
                "d + e = dzie (woda – wodzie)",
                "g + e = dze (kolega – koledze)",
                "k + e = ce (matka – matce)",
                "r + e = rze (siostra – siostrze)",
                "zd + e = ździe (gwiazda – gwieździe)",
                "dz – g (koledzy – kolegom)",
                "ć – t (klienci – klientom)"
            ])
        ],
        "Знахідний відмінок": [

            "Форми знахідного відмінка використовуються після дієслів mieć, lubić, jeść, kupować, czytać, znać, oglądać, prosić. Але якщо ці дієслова виступають в заперечувальних конструкціях, використовуємо родовий відмінок, розглянутий вище.",
            ("", None),

            {"Для іменників в однині діють наступні правила.": ""},
            "Загальне правило: Іменники-неістоти чоловічого роду, іменники середнього роду і всі іменники жіночого роду із закінченням на приголосний мають однакові форми називного і знахідного відмінків. Приклад: dom – dom.",
            {"Чоловічий рід": ""},
            ("numbered", [
                "Всі іменники чоловічого роду на позначення істот в однині мають закінчення -а. Приклад: chłop – chłopa."
            ]),

            {"Жіночий рід": ""},
            ("numbered", [
                "Якщо іменник жіночого роду в однині називного відмінка закінчується на голосний, то в знахідному він має закінчення -ę. Приклад: ulica – ulicę."
            ]),
            {"Виняток:": "pani – panią."},
            ("", None),
            ("", None),
            {"Іменники множини змінюються за такими правилами:": ""},
            "Загальне правило: Закінчення знахідного відмінка множини у іменників чоловічого роду на позначення тварин та предметів, жіночого та середнього роду співпадають із закінченнями називного відмінка множини.",
            {"Чоловічий рід": ""},
            ("numbered", [
                "Іменники-назви істот чоловічого роду (лише людей) у знахідному відмінку множини здебільшого мають закінчення -ów. Приклад: aktor – aktorów, що співпадає із закінченням у родовому відмінку.",
                "Іменники-істоти, що в називному відмінку множини закінчуються на -e, -ie, -ia, можуть мати закінчення -u або -i. Приклад: lekarze – lekarzy."
            ])
        ],
        "Орудний відмінок": [

            "З орудним відмінком використовуються прийменники z, nad, pod, między. Також дієслова dojechać, pojechać, jechać вимагають постановки залежних іменників в орудному відмінку. Ці іменники відносяться до засобів пересування (транспорту).",
            ("", None),
            {"Правила відмінювання в однині орудного відмінка:": ""},
            ("numbered", [
                "Іменники чоловічого та жіночого родів із закінченням -а в називному відмінку однини закінчуються на -ą в орудному.",
                "Інші іменники чоловічого роду та іменники середнього роду мають закінчення -em. Якщо основа закінчується на k або g, то приголосний пом’якшується з додаванням літери -iem."
            ]),
            ("", None),
            {"Правила відмінювання у множині орудного відмінка:": ""},
            ("numbered", [
                "У більшості випадків іменники в орудному відмінку множини мають закінчення -ami. Приклад: panami.",
                "Однак існує невелика група іменників, основа яких закінчується на м’який або стверділий приголосний — у таких випадках вживається закінчення -mi. Приклад: dziećmi."
            ])
        ],

        "Місцевий відмінок": [
            "Місцевий відмінок використовується після прийменників na, w, o, przy.",
            ("", None),
            {"Правила відмінювання в однині місцевого відмінка:": ""},
            {"Чоловічий та середній роди": ""},
            ("numbered", [
                "Якщо основа закінчується на тверду приголосну, то закінчення -e. Пом’якшується приголосний за допомогою -i-, тобто утворенням закінчення -ie. Приклад: okno – na oknie, sklep – w sklepie. Деякі іменники мають у корені чергування -а- з -е-. Приклад: miasto – mieście.",
                "Якщо основа леми закінчується на м’який приголосний, c, dz, cz, dż, l, rz, sż, ż або на k, g, ch, то закінчення -u."
            ]),
            {"Винятки:": "pan – panu, syn – synu, dom – domu."},

            {"Жіночий рід": ""},
            ("numbered", [
                "Коли основа слова закінчується на тверду приголосну, то закінчення -e.",
                "Якщо основа закінчується на м’який приголосний, то слово отримує закінчення -i. Приклад: pani – pani.",
                "Слова, основи яких закінчується на sz, cz, dz, dż, ż, rz, c мають закінчення -y. Приклад: noc – nocy."
            ]),
            ("", None),
            ("", None),

            {"У множині місцевого відмінка, незалежно від роду, всі іменники закінчуються на -ach.": ""}, ("Приклад: pan – panach; drzewo – drzewach.")
            ,
            {
                "Винятки:": "Niemcy – w Niemczech, Węgry – na Węgrzech, Włochy – we Włoszech, oko – oczach, imię – imionach, cielę – cielętach тощо."},
            ("", None),

            "Для місцевого відмінку також типове чергування звуків:",
            ("bullet", [
                "ch + e = sze (mucha – o musze)",
                "d + e = dzie (woda – w wodzie)",
                "g + e = dze (noga – o nodze)",
                "k + e = ce (matka – o matce)",
                "ł + e = le (stół – na stole)",
                "r + e = rze (rower – na rowerze)",
                "sł + e = śle (krzesło – na krześle)",
                "st + e = ście (miasto – w mieście)",
                "t + e = cie (uniwersytet – na uniwersytecie)",
                "zd + e = ździe (gwiazda – o gwieździe)"
            ])
        ],
        "Кличний відмінок": [

            "Характерною рисою є наявність кличного відмінка у польській мові — він, як і в українській, використовується для звертання. Кличний відмінок має форми лише для іменників чоловічого та жіночого роду в однині. У всіх інших випадках, тобто для однини середнього роду та множини, кличний відмінок має таку ж форму як і в називному відмінку. Але у неформальному спілкуванні часто замість кличного відмінка вживається форма називного, особливо для імен. Якщо при звертанні ім’я вживається зі словами pan чи pani, то воно ставиться в кличному відмінку. Приклад: panie Pawle. З прізвищами вживається тільки називний відмінок однини. Приклад: pani Massur.",
            ("", None),
            {"Правила відмінювання в однині кличного відмінка:": ""},

            {"Чоловічий рід": ""},
            ("numbered", [
                "Іменники із закінченням на -а змінюють закінчення -о. Приклад: tato.",
                "Якщо основа на твердий приголосний (b, p, n, m, w, f, s, z), іменник має закінчення -ie. Приклад: Filip – Filipie.",
                "Якщо основа на м’який приголосний, іменники з закінченням на -k, -g, -ch та пестливі жіночі імена мають закінчення -u. Приклад: Tomasz – Tomaszu, Marek – Mareku, Basia – Basiu. При закінченнях -ek — буква e випадає."
            ]),
            "Також можливі чергування:",
            ("bullet", [
                "t – cie (student – studencie)",
                "d – dzie (sąsiad – sąsiedzie)",
                "r – rze (dyrektor – dyrektorze)",
                "ł – le (poseł – pośle)"
            ]),
            "Якщо слово закінчується на -(i)ec, то закінчення -cze. Приклад: chłopiec – chłopcze.",
            {"Винятки:": "Bóg – Boże; gołąb – gołębiu; ksiądz – księże."},

            {"Жіночий рід": ""},
            ("numbered", [
                "Якщо слово закінчується на -ja, -la, -cia, -dzia, -nia, -sia, -zia, то закінчення -u (часто зменшувально-пестливі слова).",
                "Іменники на -і або на м’який приголосний мають у кличному відмінку однини закінчення -і.",
                "Іменники з твердими приголосними закінчуються на -у.",
                "Також, як і в українській, використовується закінчення -o. Приклад: mama – mamo."
            ])]
    }

    def show_theory(title):
        show_content(title, theory_content.get(title, [{"Помилка": f"Вміст для '{title}' не знайдено."}]))
        canvas.yview_moveto(0)

    cases = ["Іменник", "Називний відмінок", "Родовий відмінок",
             "Давальний відмінок", "Знахідний відмінок",
             "Орудний відмінок", "Місцевий відмінок", "Кличний відмінок"]
    for case_name in cases:
        btn = tk.Button(
            nav_frame,
            text=case_name, 
            relief="flat",
            bg="#A3EEFF", fg="black",
            font=("Montserrat", 12),
            justify="center",
            command=lambda c=case_name: show_theory(c))
        btn.pack(fill="x", pady=2)
    show_theory("Іменник")

def get_random_word(single=True):
    if single:
        pol_cursor.execute(
            "SELECT sgN, plN FROM tnoun WHERE sgN != '' AND sgN IS NOT NULL AND plN != '' AND plN IS NOT NULL ORDER BY RANDOM() LIMIT 1")
    else:
        pol_cursor.execute("SELECT sgN, plN FROM tnoun WHERE plN != '' AND plN IS NOT NULL ORDER BY RANDOM() LIMIT 1")
    return pol_cursor.fetchone()


def show_testing():
    global main_win, current_user_email
    configure_window(main_win, 1000, 800)
    clear_frame(main_win)

    tk.Button(main_win,
              text="← Назад",
              command=lambda: open_main_window(current_user_email),
              width=12, height=1,
              bg="#E0E0E0", fg="black", font=("Montserrat", 12)
              ).pack(anchor='nw', pady=10, padx=10)

    tk.Label(main_win,
             text="Оберіть розділ тестування",
             font=("Montserrat", 16, 'bold'),
             bg="#f4f6f8"
             ).pack(pady=30)

    sections_tests = [
        ("Називний відмінок", show_nominative_test, "#A3EEFF"),
        ("Родовий відмінок", show_genitive_test, "#A3EEFF"),
        ("Давальний відмінок", show_dative_test, "#A3EEFF"),
        ("Знахідний відмінок", show_accusative_test, "#A3EEFF"),
        ("Орудний відмінок", show_instrumental_test, "#A3EEFF"),
        ("Місцевий відмінок", show_locative_test, "#A3EEFF"),
        ("Кличний відмінок", show_vocative_test, "#A3EEFF"),
        ("Комплексний тест",show_matching_test, "#A3EEFF"),
    ]

    for sec_name, cmd_func, bg_color in sections_tests:
        tk.Button(main_win,
                  text=sec_name,
                  command=cmd_func,
                  width=30, height=2, bg=bg_color, fg="black", font=("Montserrat", 12)).pack(pady=5)

def _show_results_in_window(parent, result_text):
    win = tk.Toplevel(parent)
    win.title("Результат")
    txt = tk.Text(
        win,
        wrap="word",
        width=60, height=20, font=("Montserrat", 10), fg="black")
    txt.insert("1.0", result_text)
    txt.config(state="disabled")
    txt.pack(side="left", fill="both", expand=True)

    sb = tk.Scrollbar(win, command=txt.yview, orient="vertical")
    txt.configure(yscrollcommand=sb.set)
    sb.pack(side="right", fill="y")

def show_nominative_test():
    global main_win, current_test_func
    current_test_func = show_nominative_test
    clear_frame(main_win)

    tk.Button(main_win,
              text="← Назад",
              command=show_testing,
              width=12, height=1,
              bg="#E0E0E0", fg="black", font=("Montserrat", 12)
              ).pack(anchor='nw', pady=10, padx=10)

    tk.Label(main_win,
             text="Тест: Називний відмінок",
             font=("Montserrat", 16, 'bold'),
             bg="#f4f6f8"
             ).pack(pady=(5, 5))

    instruction_label = tk.Label(main_win,
                                 text=(
                                     "Інструкція: Вам подається слово у формі однини або множини називного відмінка (kto? co?). "
                                     "Оберіть правильну форму називного відмінка."
                                 ),
                                 font=("Montserrat", 12), bg="#f4f6f8", padx=10)
    instruction_label.pack(pady=(0, 20), fill=tk.X)

    main_win.update_idletasks()
    if instruction_label.winfo_exists():
        instruction_label.config(wraplength=instruction_label.winfo_width())

    questions = []
    count_sg_pl = 0
    attempts_sg_pl = 0
    while count_sg_pl < 5 and attempts_sg_pl < 100:
        attempts_sg_pl += 1
        word_data = get_random_word(single=True)
        if not word_data or not word_data[0] or not word_data[1]:
            continue
        sgN, plN = word_data

        pol_cursor.execute(
            "SELECT sgN, sgG, sgD, sgA, sgI, sgL, sgV, plN, plG, plD, plA, plI, plL, plV "
            "FROM tnoun WHERE sgN=? AND plN=?", (sgN, plN)
        )
        row_forms_tuple = pol_cursor.fetchone()
        if not row_forms_tuple: continue

        all_forms_for_word = [f for f in row_forms_tuple if f and f.strip()]
        distractors = list(set(f for f in all_forms_for_word if f != plN))

        if not distractors:
            pol_cursor.execute(
                "SELECT DISTINCT plN FROM tnoun WHERE plN != ? AND plN != '' AND plN IS NOT NULL ORDER BY RANDOM() LIMIT 3",
                (plN,))
            extra_distractors = [r[0] for r in pol_cursor.fetchall()]
            distractors.extend(extra_distractors)
            distractors = list(set(distractors))
            if not distractors: continue

        current_options = [plN] + random.sample(distractors, min(3, len(distractors)))
        current_options = list(dict.fromkeys(current_options))
        random.shuffle(current_options)

        if len(current_options) > 4:
            current_options = random.sample(current_options, 4)
            if plN not in current_options:
                if current_options:
                    current_options[random.randint(0, len(current_options) - 1)] = plN
                else:
                    current_options = [plN]
                current_options = list(dict.fromkeys(current_options))
                random.shuffle(current_options)
        elif plN not in current_options:
            if len(current_options) < 4:
                current_options.append(plN)
            elif current_options:
                current_options[random.randint(0, len(current_options) - 1)] = plN
            else:
                current_options = [plN]
            current_options = list(dict.fromkeys(current_options))
            random.shuffle(current_options)

        if len(current_options) < 2: continue

        questions.append({'q': f'Яка форма множини слова "{sgN}"?', 'opts': current_options, 'ans': plN})
        count_sg_pl += 1

    count_pl_sg = 0
    attempts_pl_sg = 0
    while count_pl_sg < 5 and attempts_pl_sg < 100:
        attempts_pl_sg += 1
        word_data = get_random_word(single=False)
        if not word_data or not word_data[1]: continue
        sgN_orig, plN_orig = word_data
        correct_answer = sgN_orig if (sgN_orig and sgN_orig.strip()) else 'pluralia tantum'

        query_conditions = "plN=?"
        params = [plN_orig]
        if sgN_orig and sgN_orig.strip():
            query_conditions += " AND sgN=?"
            params.append(sgN_orig)
        else:
            query_conditions += " AND (sgN IS NULL OR sgN = '')"

        pol_cursor.execute(
            f"SELECT sgN, sgG, sgD, sgA, sgI, sgL, sgV, plN, plG, plD, plA, plI, plL, plV "
            f"FROM tnoun WHERE {query_conditions}", tuple(params)
        )
        row_forms_tuple = pol_cursor.fetchone()
        if not row_forms_tuple: continue

        all_forms_for_word = [f for f in row_forms_tuple if f and f.strip()]
        distractors = list(set(f for f in all_forms_for_word if f != correct_answer))

        if not distractors:
            pol_cursor.execute(
                "SELECT DISTINCT sgN FROM tnoun WHERE sgN != ? AND sgN != '' AND sgN IS NOT NULL AND sgN != 'pluralia tantum' ORDER BY RANDOM() LIMIT 3",
                (correct_answer,))
            extra_distractors = [r[0] for r in pol_cursor.fetchall()]
            if correct_answer == 'pluralia tantum':
                pass
            elif 'pluralia tantum' not in extra_distractors and len(extra_distractors) < 3:
                extra_distractors.append('pluralia tantum')

            distractors.extend(extra_distractors)
            distractors = list(set(distractors))
            if not distractors: continue

        current_options = [correct_answer] + random.sample(distractors, min(3, len(distractors)))
        current_options = list(dict.fromkeys(current_options))
        random.shuffle(current_options)

        if len(current_options) > 4:
            current_options = random.sample(current_options, 4)
            if correct_answer not in current_options:
                if current_options:
                    current_options[random.randint(0, len(current_options) - 1)] = correct_answer
                else:
                    current_options = [correct_answer]
                current_options = list(dict.fromkeys(current_options))
                random.shuffle(current_options)
        elif correct_answer not in current_options:
            if len(current_options) < 4:
                current_options.append(correct_answer)
            elif current_options:
                current_options[random.randint(0, len(current_options) - 1)] = correct_answer
            else:
                current_options = [correct_answer]
            current_options = list(dict.fromkeys(current_options))
            random.shuffle(current_options)

        if len(current_options) < 2: continue

        questions.append({'q': f'Яка форма однини слова "{plN_orig}"?', 'opts': current_options, 'ans': correct_answer})
        count_pl_sg += 1

    if not questions:
        tk.Label(main_win, text="Не вдалося згенерувати достатньо питань для тесту. Спробуйте ще раз.",
                 font=("Montserrat", 12), bg="#f4f6f8", fg="red").pack(pady=20)
        return

    q_frame_outer = tk.Frame(main_win, bg="#f4f6f8")
    q_frame_outer.pack(fill="both", expand=True, padx=20)

    canvas = tk.Canvas(q_frame_outer, bg="#f4f6f8", highlightthickness=0)
    sb = tk.Scrollbar(q_frame_outer, orient="vertical", command=canvas.yview)
    inner_q_frame = tk.Frame(canvas, bg="#f4f6f8")

    canvas_window = canvas.create_window((0, 0), window=inner_q_frame, anchor="nw")
    canvas.configure(yscrollcommand=sb.set)

    canvas.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")

    q_text_labels_to_wrap = []
    rb_labels_to_wrap = []

    vars_list = []
    for idx, item in enumerate(questions, 1):
        q_item_frame = tk.Frame(inner_q_frame, bg="#f4f6f8")
        q_item_frame.pack(fill="x", pady=5, padx=5)

        q_text_label = tk.Label(q_item_frame, text=f"{idx}. {item['q']}",
                                font=("Montserrat", 12, "bold"), bg="#f4f6f8",
                                anchor="w", justify="left")
        q_text_label.pack(fill="x", anchor="w")
        q_text_labels_to_wrap.append(q_text_label)

        v = tk.StringVar(value="__NONE__")
        vars_list.append((v, item['ans']))

        for option_text in item['opts']:
            if option_text:
                rb = tk.Radiobutton(q_item_frame, text=option_text, variable=v, value=option_text,
                                    font=("Montserrat", 11), bg="#f4f6f8",
                                    anchor="w", justify="left")
                rb.pack(fill="x", anchor="w", padx=20)
                rb_labels_to_wrap.append(rb)

    def _configure_canvas_items_wraplength(event_obj=None):  # Зробив event_obj опціональним
        current_canvas_width = canvas.winfo_width()

        if current_canvas_width > 0:
            canvas.itemconfig(canvas_window, width=current_canvas_width)
            # inner_q_frame.config(width=current_canvas_width) # Не встановлюємо тут, щоб уникнути рекурсії

            for label in q_text_labels_to_wrap:
                if label.winfo_exists():
                    label.config(wraplength=current_canvas_width - 40)
            for rb_label in rb_labels_to_wrap:
                if rb_label.winfo_exists():
                    rb_label.config(wraplength=current_canvas_width - 70)

        if inner_q_frame.winfo_exists():  # Оновлюємо scrollregion після зміни wraplength
            inner_q_frame.update_idletasks()
        canvas.config(scrollregion=canvas.bbox("all"))

    canvas.bind('<Configure>', _configure_canvas_items_wraplength)

    main_win.update_idletasks()
    _configure_canvas_items_wraplength()

    submit_button = tk.Button(main_win,
                              text="Перевірити відповіді",
                              width=20, height=2,
                              bg="#4CAF50", fg="white", font=("Montserrat", 12))

    def submit_test_nom():
        result_lines = []
        correct_count = 0

        for idx_ans, (var_obj, correct_ans_val) in enumerate(vars_list, 1):
            user_choice = var_obj.get()
            display_choice = user_choice if user_choice != "__NONE__" else "Не вибрано"
            mark = "✔" if user_choice == correct_ans_val else "✖"
            result_lines.append(
                f"{idx_ans}. Ваш вибір: {display_choice} | Правильна форма: {correct_ans_val} {mark}"
            )
            if user_choice == correct_ans_val:
                correct_count += 1

        summary = "\n".join(result_lines)
        full_text = f"Правильно {correct_count} з {len(vars_list)}:\n\n{summary}"
        update_user_stats('N', correct_count, len(vars_list))
        _show_results_in_window(main_win, full_text)
        submit_button.config(state=tk.DISABLED, bg="#A0A0A0", text="Результат показано")


    submit_button.config(command=submit_test_nom)
    submit_button.pack(pady=(10, 20))
    restart_btn = tk.Button(main_win,
                            text="Почати новий тест", width=20, height=2, bg="#C3E7EF", fg="black", font=("Montserrat", 12), command=current_test_func)
    restart_btn.pack(side="bottom", pady=(0, 10))

CASE_CODES = ['N', 'G', 'D', 'A', 'I', 'L', 'V']
CASE_LABELS = {
    'N': 'називного відмінка',
    'G': 'родового відмінка',
    'D': 'давального відмінка',
    'A': 'знахідного відмінка',
    'I': 'орудного відмінка',
    'L': 'місцевого відмінка',
    'V': 'кличного відмінка'
}

CASE_QUESTION_MAP = {
    ("sgN", "plN"): "kto? co?",
    ("sgG", "plG"): "kogo? czego?",
    ("sgD", "plD"): "komu? czemu?",
    ("sgA", "plA"): "kogo? co?",
    ("sgI", "plI"): "kim? czym?",
    ("sgL", "plL"): "o kim? o czym?",
    ("sgV", "plV"): "hej!"
}
#допоміжні ф-ції
def make_opts(correct, forms):
    pool = [f for f in set(forms) if f and f != correct]
    return random.sample(pool, min(3, len(pool)))

def fetch_random_row_full():
    pol_cursor.execute(
        "SELECT sgN, plN, sgG, plG, sgD, sgA, sgI, sgL, sgV, plD, plA, plI, plL, plV"
        " FROM tnoun ORDER BY RANDOM() LIMIT 1"
    )
    cols = pol_cursor.fetchone()
    if not cols:
        return None
    keys = ['sgN','plN','sgG','plG','sgD','sgA','sgI','sgL','sgV','plD','plA','plI','plL','plV']
    return dict(zip(keys, cols))

def generate_case_questions(case_code):
    case_label = CASE_LABELS.get(case_code, '')
    #Тип 1: Multiple Choice
    questions = []
    #2 питання на однину
    for _ in range(2):
        sgN, plN = get_random_word(single=True)
        pol_cursor.execute(
            f"SELECT sg{case_code}, sgN, sgG, sgD, sgA, sgI, sgL, sgV, plN FROM tnoun WHERE sgN=? AND plN=?",
            (sgN, plN)
        )
        row = pol_cursor.fetchone()
        if not row:
            continue
        correct = row[0]
        forms = row[2:8]
        opts = [correct] + make_opts(correct, forms)
        random.shuffle(opts)
        questions.append({
            'q': sgN,
            'opts': opts,
            'ans': correct,
            'num': f"форму однини {case_label}"
        })
    #2 питання на множину
    for _ in range(2):
        sgN, plN = get_random_word(single=True)
        pol_cursor.execute(
            f"SELECT pl{case_code}, sg{case_code}, sgN, sgG, sgD, sgA, sgI, sgL, sgV, plN FROM tnoun WHERE sgN=? AND plN=?",
            (sgN, plN)
        )
        row = pol_cursor.fetchone()
        if not row:
            continue
        correct = row[0]
        forms = row[1:7]
        opts = [correct] + make_opts(correct, forms)
        random.shuffle(opts)
        questions.append({
            'q': sgN,
            'opts': opts,
            'ans': correct,
            'num': f"форму множини {case_label}"
        })

    #Тип 2: Так/Ні
    yn_questions = []
    used = set()
    #правильні
    while len([q for q in yn_questions if q['correct']]) < 2:
        row = fetch_random_row_full()
        if not row:
            continue
        is_sg = random.choice([True, False])
        key = 'sg' + case_code if is_sg else 'pl' + case_code
        form = row[key]
        if form and form not in used:
            used.add(form)
            num = 'однини' if is_sg else 'множини'
            yn_questions.append({
                'form': form,
                'correct': True,
                'answer': form,
                'num': num,
                'case_code': case_code  # ← add this
            })
    #неправильні
    while len([q for q in yn_questions if not q['correct']]) < 2:
        row = fetch_random_row_full()
        if not row:
            continue
        is_sg = random.choice([True, False])
        key = 'sg' + case_code if is_sg else 'pl' + case_code
        correct_form = row[key]
        pool_keys = ['sgG','sgD','sgA','sgI','sgL','sgV'] if is_sg else ['plD','plA','plI','plL','plV']
        distractors = [row[k] for k in pool_keys if row[k] and row[k] != correct_form]
        if not distractors:
            continue
        form = random.choice(distractors)
        if form not in used:
            used.add(form)
            num = 'однини' if is_sg else 'множини'
            yn_questions.append({
                'form': form,
                'correct': False,
                'answer': correct_form,
                'num': num,
                'case_code': case_code  # ← add this
            })
    random.shuffle(yn_questions)

    # Тип 3: Вільний ввід
    text_questions = []
    key_tuple = (f"sg{case_code}", f"pl{case_code}")
    question_prompt = CASE_QUESTION_MAP.get(key_tuple, "")

    # 2 питання на однину
    for _ in range(2):
        row = fetch_random_row_full()
        if not row:
            continue
        base = row['sgN'] if row['sgN'] else row['plN']
        text_questions.append({
            'base': base,
            'num': f"форму однини {case_label} ({question_prompt})",
            'ans': row['sg' + case_code]
        })

    # 2 питання на множину
    for _ in range(2):
        row = fetch_random_row_full()
        if not row:
            continue
        base = row['sgN'] if row['sgN'] else row['plN']
        text_questions.append({
            'base': base,
            'num': f"форму множини {case_label} ({question_prompt})",
            'ans': row['pl' + case_code]
        })
    return questions, yn_questions, text_questions

def render_test(case_ua, case_code, main_win, questions, yn_questions, text_questions):
    clear_frame(main_win)
    tk.Button(main_win, text="← Назад", command=show_testing,
              width=12, height=1, bg="#E0E0E0", fg="black",
              font=("Montserrat",12)).pack(anchor='nw', pady=10, padx=10)
    tk.Label(main_win, text=f"Тест: {case_ua} відмінок",
             font=("Montserrat",16,'bold'), bg="#f4f6f8").pack(pady=(20,5))
    question_pair = CASE_QUESTION_MAP.get(('sg' + case_code, 'pl' + case_code), '')
    instr = tk.Label(main_win,
                     text=(
                         "Інструкція:\n"
                         f"Питання 1–4. Для кожного слова в називному відмінку однини оберіть правильну форму {CASE_LABELS[case_code]} ({question_pair}).\n"
                         "Питання 5–8. Для кожної словоформи натисніть «Так», якщо вона відповідає питанню, або «Ні» — якщо ні.\n"
                         "Питання 9–12. Введіть у поле правильну словоформу польською. За потреби використовуйте діакритичні символи.\n"
                         "Кожне питання дає 1 бал."),
                     font=("Montserrat",12), bg="#f4f6f8",
                     wraplength=700, justify="left")
    instr.pack(pady=(0,20), padx=20)

    frame = tk.Frame(main_win, bg="#f4f6f8")
    frame.pack(fill="both", expand=True, padx=20)
    canvas = tk.Canvas(frame, bg="#f4f6f8", highlightthickness=0)
    scroll = tk.Scrollbar(frame, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg="#f4f6f8")
    canvas.create_window((0,0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=scroll.set)
    scroll.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    vars_mcq, vars_bool, vars_text = [], [], []

    #тест
    for i, itm in enumerate(questions, 1):
        f = tk.Frame(inner, bg="#f4f6f8"); f.pack(fill="x", pady=5)
        tk.Label(f, text=f"{i}. Поставте слово '{itm['q']}' у {itm['num']}.",
                 font=("Montserrat",12,"bold"), bg="#f4f6f8").pack(anchor="w")
        v = tk.StringVar(value="__NONE__")
        vars_mcq.append((v, itm['ans']))
        for o in itm['opts']:
            tk.Radiobutton(f, text=o, variable=v, value=o,
                           font=("Montserrat",11), bg="#f4f6f8").pack(anchor="w", padx=20)

    #Так/Ні
    start = len(questions)
    for j, q in enumerate(yn_questions, 1):
        idx = start + j
        f2 = tk.Frame(inner, bg="#f4f6f8")
        f2.pack(fill="x", pady=5)

        case_label = CASE_LABELS[q['case_code']]

        question = f"{idx}. Чи відповідає форма '{q['form']}' формі {q['num']} {case_label}?"
        tk.Label(f2, text=question,
                 font=("Montserrat", 12, "bold"),
                 bg="#f4f6f8").pack(anchor="w")

        v2 = tk.StringVar(value="__NONE__")
        vars_bool.append((v2, q))
        tk.Radiobutton(f2, text="Так", variable=v2, value="yes",
                       font=("Montserrat", 11), bg="#f4f6f8") \
            .pack(anchor="w", padx=20)
        tk.Radiobutton(f2, text="Ні", variable=v2, value="no",
                       font=("Montserrat", 11), bg="#f4f6f8") \
            .pack(anchor="w", padx=20)

    #ввід
    start2 = start + len(yn_questions)
    special_chars = ['ą','ć','ę','ł','ń','ó','ś','ź','ż']
    for k, t in enumerate(text_questions, 1):
        idx = start2 + k
        f3 = tk.Frame(inner, bg="#f4f6f8"); f3.pack(fill="x", pady=5)
        tk.Label(f3, text=f"{idx}. Поставте слово '{t['base']}' у {t['num']}.",
                 font=("Montserrat",12,"bold"), bg="#f4f6f8").pack(anchor="w")
        e = tk.Entry(f3, font=("Montserrat",11), width=20)
        e.pack(anchor="w", padx=20)
        kb = tk.Frame(f3, bg="#f4f6f8")
        for ch in special_chars:
            tk.Button(kb, text=ch, width=2, font=("Montserrat",11), bg="#e0e0e0",
                      command=lambda c=ch, ent=e: ent.insert('insert', c)).pack(side="left", padx=1)
        kb.pack(anchor="w", padx=20, pady=5)
        vars_text.append((e, t['ans']))

    check_btn = tk.Button(main_win, text="Перевірити відповіді",
                          width=20, height=2, bg="#4CAF50",
                          fg="white", font=("Montserrat",12))
    def submit_test_global():
        score = 0
        lines = []
        total = len(vars_mcq) + len(vars_bool) + len(vars_text)
        idx = 0
        # MCQ
        for var, correct in vars_mcq:
            idx += 1
            res = var.get()
            mark = "✔" if res == correct else "✖"
            display = res if res != "__NONE__" else "Не вибрано"
            if res == correct:
                score += 1
            lines.append(f"{idx}. Ваш вибір: {display} | Правильна форма: {correct} {mark}")
        # Так/Ні
        for var, info in vars_bool:
            idx += 1
            res = var.get()
            corr = "yes" if info['correct'] else "no"
            mark = "✔" if res == corr else "✖"
            if res == corr:
                score += 1
            display = "Так" if res == "yes" else "Ні" if res == "no" else "Не вибрано"
            lines.append(f"{idx}. Ваш вибір: {display} | Правильна форма: {info['answer']} {mark}")
        # Вільний ввід
        for ent, ans in vars_text:
            idx += 1
            val = ent.get().strip().lower()
            mark = "✔" if val == ans.lower() else "✖"
            if val == ans.lower():
                score += 1
            lines.append(f"{idx}. Ваш варіант: {ent.get()} | Правильна форма: {ans} {mark}")
        full_text = f"Правильно {score} з {total}:\n\n" + "\n".join(lines)
        update_user_stats(case_code, score, total)
        _show_results_in_window(main_win, full_text)
        check_btn.config(state=tk.DISABLED, bg="#A0A0A0", text="Перевірено")

    check_btn.config(command=submit_test_global)
    check_btn.pack(pady=20)
    restart_btn = tk.Button(main_win,
                            text="Почати новий тест", width=20, height=2, bg="#C3E7EF", fg="black", font=("Montserrat", 12), command=current_test_func)
    restart_btn.pack(side="bottom", pady=(0, 10))

#створення тестів за шаблоном
def show_genitive_test():
    global current_test_func
    current_test_func = show_genitive_test
    qs, yns, ts = generate_case_questions('G')
    render_test('Родовий', 'G', main_win, qs, yns, ts)

def show_dative_test():
    global current_test_func
    current_test_func = show_dative_test
    qs, yns, ts = generate_case_questions('D')
    render_test('Давальний', 'D', main_win, qs, yns, ts)

def show_accusative_test():
    global current_test_func
    current_test_func = show_accusative_test
    qs, yns, ts = generate_case_questions('A')
    render_test('Знахідний', 'A', main_win, qs, yns, ts)

def show_instrumental_test():
    global current_test_func
    current_test_func = show_instrumental_test
    qs, yns, ts = generate_case_questions('I')
    render_test('Орудний', 'I', main_win, qs, yns, ts)

def show_locative_test():
    global current_test_func
    current_test_func = show_locative_test
    qs, yns, ts = generate_case_questions('L')
    render_test('Місцевий', 'L', main_win, qs, yns, ts)

def show_vocative_test():
    global current_test_func
    current_test_func = show_vocative_test
    qs, yns, ts = generate_case_questions('V')
    render_test('Кличний', 'V', main_win, qs, yns, ts)

PLAIN_CASE = {
    'N': 'називний відмінок',
    'G': 'родовий відмінок',
    'D': 'давальний відмінок',
    'A': 'знахідний відмінок',
    'I': 'орудний відмінок',
    'L': 'місцевий відмінок',
    'V': 'кличний відмінок',
    'C': 'комплексний тест'
}

def show_matching_test():
    global main_win, current_test_func
    current_test_func = show_matching_test
    clear_frame(main_win)

    tk.Button(main_win, text="← Назад", command=show_testing,
              width=12, height=1, bg="#E0E0E0", fg="black",
              font=("Montserrat", 12)).pack(anchor='nw', pady=10, padx=10)

    tk.Label(main_win, text="Комплексний тест: Відповідність форм",
             font=("Montserrat", 16, 'bold'), bg="#f4f6f8") \
        .pack(pady=(10, 5))

    instr = tk.Label(main_win,
                     text="Для кожної словоформи оберіть правильний відмінок та число.\n"
                          "Якщо форма зустрічається кілька разів, кожен унікальний варіант зараховується тільки один раз.",
                     font=("Montserrat", 12), bg="#f4f6f8", wraplength=700, justify="left")
    instr.pack(pady=(0, 10), padx=20)

    #Підготовка всіх варіантів відповіді
    all_options = ["– оберіть –"]  #опцію за замовчуванням на початок
    for code in CASE_CODES:
        lbl = PLAIN_CASE[code]
        all_options += [f"{lbl}, однина", f"{lbl}, множина"]

    keys_order = [
        'sgN', 'sgG', 'sgD', 'sgA', 'sgI', 'sgL', 'sgV',
        'plN', 'plG', 'plD', 'plA', 'plI', 'plL', 'plV'
    ]

    #Прокручувана зона
    container = tk.Frame(main_win, bg="#f4f6f8")
    container.pack(fill="both", expand=True, padx=10, pady=5)
    canvas = tk.Canvas(container, bg="#f4f6f8", highlightthickness=0)
    vsb = tk.Scrollbar(container, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)
    inner = tk.Frame(canvas, bg="#f4f6f8")
    canvas.create_window((0, 0), window=inner, anchor="nw")
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))

    #Збираємо Combobox-и у групи за самою словоформою
    form_groups = {}

    questions_data_for_submit = []

    for qi in range(1, 6):  #Ітерація по 5 питаннях
        row = fetch_random_row_full()
        if not row:
            print(f"Warning: fetch_random_row_full returned None for question {qi}.")
            continue  # Пропустити ітерацію, якщо даних немає

        base_word_for_title = row.get('sgN', '')
        if not base_word_for_title:
            base_word_for_title = row.get('plN', '(слово не знайдено)')

        question_title = f"Питання {qi}: слово '{base_word_for_title}'"
        tk.Label(inner, text=question_title,
                 font=("Montserrat", 12, "bold"), bg="#f4f6f8") \
            .pack(anchor="w", pady=(15, 4))

        tbl = tk.Frame(inner, bg="#f4f6f8")
        tbl.pack(fill="x", pady=2)

        pairs = [(k, row[k]) for k in keys_order if row.get(k)]
        random.shuffle(pairs)

        current_question_forms_for_submit = []

        if not pairs and not row:
            print(f"Warning: No forms to display for question {qi}, word '{base_word_for_title}'.")
            continue

        for idx, (key, form) in enumerate(pairs):
            r = idx % 7
            c = (idx // 7) * 2

            tk.Label(tbl, text=form, font=("Montserrat", 11), bg="#f4f6f8").grid(row=r, column=c, sticky="w", padx=5, pady=2)

            cb = ttk.Combobox(tbl, values=all_options,
                              state="readonly", width=25,  #
                              font=("Montserrat", 11))
            cb.grid(row=r, column=c + 1, padx=5, pady=2)
            cb.set("– оберіть –")

            num = "однина" if key.startswith("sg") else "множина"

            case_char_from_key = key[2]  # N, G, D, A, I, L, V
            correct_label = f"{PLAIN_CASE[case_char_from_key]}, {num}"

            form_groups.setdefault(form, []).append((cb, correct_label))
            current_question_forms_for_submit.append({
                "form_text": form,
                "combobox": cb
            })

        if current_question_forms_for_submit:
            questions_data_for_submit.append({
                "title": question_title,
                "forms_and_cbs": current_question_forms_for_submit
            })

    #Кнопка перевірки
    def submit_test_matching(questions_data_param, all_form_groups_param, button_to_disable):
        score = 0
        total = sum(len(group) for group in all_form_groups_param.values())

        master_allowed_counters = {}
        for form_text, group_of_cbs_and_labels in all_form_groups_param.items():
            master_allowed_counters[form_text] = Counter(lbl for _, lbl in group_of_cbs_and_labels)

        result_parts_by_question = []

        for question_info in questions_data_param:
            question_title = question_info["title"]
            forms_and_cbs_in_question = question_info["forms_and_cbs"]
            current_question_result_lines = [f"{question_title}"]

            for item in forms_and_cbs_in_question:
                form_text = item["form_text"]
                cb_widget = item["combobox"]
                pick = cb_widget.get()

                current_form_master_counter = master_allowed_counters.get(form_text)
                if current_form_master_counter is None:
                    current_question_result_lines.append(
                        f"  «{form_text}»: {pick} ✖  (помилка: форма не знайдена в лічильниках)")
                    continue

                if current_form_master_counter.get(pick, 0) > 0:
                    current_form_master_counter[pick] -= 1
                    score += 1
                    current_question_result_lines.append(f"  «{form_text}»: вибір «{pick}» ✔")
                else:
                    remaining_for_hint = [lbl for lbl, cnt in current_form_master_counter.items() if cnt > 0]
                    hint = " / ".join(remaining_for_hint) if remaining_for_hint else "(немає варіантів)"
                    display = "не вибрано" if pick == "– оберіть –" else pick
                    current_question_result_lines.append(
                        f"  «{form_text}»: {display} ✖  (правильно: {hint})")

            result_parts_by_question.append("\n".join(current_question_result_lines))

        final_detailed_results = "\n\n".join(result_parts_by_question)  # Подвійний перенос рядка між питаннями
        full_text = f"Правильно {score} з {total}:\n\n{final_detailed_results}"
        update_user_stats('C', score, total)
        _show_results_in_window(main_win, full_text)
        if button_to_disable:
            button_to_disable.config(state=tk.DISABLED, bg="#A0A0A0", text="Перевірено")

    restart_btn = tk.Button(
        main_win,
        text="Почати новий тест",
        width=20, height=2,
        bg="#C3E7EF", fg="black",
        font=("Montserrat", 12),
        command=current_test_func)
    restart_btn.pack(side="bottom", pady=(0, 20))

    submit_btn = tk.Button(
        main_win,
        text="Перевірити відповіді",
        width=20, height=2,
        bg="#4CAF50", fg="white",
        font=("Montserrat", 12),
        command=lambda: submit_test_matching(questions_data_for_submit, form_groups, submit_btn))
    submit_btn.pack(side="bottom", pady=(10, 20))

def show_about_app():
    global main_win, current_user_email
    configure_window(main_win, 1000, 550)
    clear_frame(main_win)

    tk.Button(main_win,
              text="← Назад",
              command=lambda: open_main_window(current_user_email),
              width=12, height=1,
              bg="#E0E0E0", fg="black", font=("Montserrat", 12))\
        .pack(anchor='nw', pady=10, padx=10)

    tk.Label(main_win,
             text="Про додаток",
             font=("Montserrat", 16, 'bold'),
             bg="#f4f6f8")\
        .pack(pady=(20, 5))

    content_frame = tk.Frame(main_win, bg="#f4f6f8")
    content_frame.pack(fill="both", expand=True, padx=20, pady=10)

    canvas = tk.Canvas(content_frame, bg="#f4f6f8", highlightthickness=0)
    vsb = tk.Scrollbar(content_frame, orient="vertical", command=canvas.yview)
    canvas.configure(yscrollcommand=vsb.set)
    vsb.pack(side="right", fill="y")
    canvas.pack(side="left", fill="both", expand=True)

    inner = tk.Frame(canvas, bg="#f4f6f8")
    canvas.create_window((0, 0), window=inner, anchor="nw")

    def on_configure(event):
        canvas.configure(scrollregion=canvas.bbox("all"))
        label.config(wraplength=event.width - 40)

    inner.bind("<Configure>", on_configure)

    about_text = (
        "Додаток «RzeczFlex» — це електронний засіб навчання, призначений для ефективного засвоєння теми відмінювання іменників польської мови. "
        "Його створено для українськомовних користувачів з різним рівнем знань польської мови (від початкового до середнього), які бажають поглибити знання граматики "
        "і закріпити навички правильного використання іменникових форм.\n\n"
        "Основна мета додатку — надати вам зручний інструмент для системного опанування граматичних аспектів польської мови, "
        "а саме відмінкових форм 510 найчастотніших польських іменників. Подане вам тестування базується на цих словах, "
        "а додаток «RzeczFlex» поєднує в собі теоретичні пояснення та інтерактивні вправи, що допоможуть вам ефективно закріпити "
        "та практично застосувати вивчений матеріал.\n\n"
        "Кожен тестовий блок супроводжується детальною інструкцією, з якою вам слід ознайомитися перед початком проходження тесту — саме вона містить умови "
        "та формулювання завдань, на які потрібно орієнтуватися.\n\n"
        "Після завершення тесту ви отримаєте можливість один раз переглянути результати: ваші відповіді, правильні варіанти та підсумкову оцінку. "
        "За кожну правильну відповідь нараховується один бал. Усі результати зберігаються у системі автоматично, однак повторний перегляд конкретного тесту "
        "після завершення не передбачено. Тому уважно аналізуйте надану інформацію одразу після проходження тесту — це допоможе вам краще зрозуміти допущені помилки "
        "та покращити результати в майбутньому.\n\n"
        "У розділі статистики ви можете стежити за власним прогресом: додаток автоматично підраховує кількість правильних відповідей для кожного відмінка окремо, "
        "що дозволяє вам бачити динаміку опанування матеріалу.\n\n"
        "Нехай щастить!"
    )

    label = tk.Label(inner,
                     text=about_text,
                     font=("Montserrat", 12),
                     bg="#f4f6f8",
                     justify="left",
                     wraplength=920)  # початкове значення
    label.pack(fill="x", padx=20, pady=(0, 20))

#Стартове вікно
root = tk.Tk()
root.title("RzeczFlex")
configure_window(root, 380, 430)
root.configure(bg="#f4f6f8")

#Створюємо фрейми один раз і зберігаємо їх глобально
selection_frame = tk.Frame(root, bg="#f4f6f8")
login_frame = tk.Frame(root, bg="#f4f6f8")
register_frame = tk.Frame(root, bg="#f4f6f8")


def create_selection_frame_content(parent_frame):  #Функція для створення вмісту selection_frame
    clear_frame(parent_frame)
    #Контейнер по центру
    container = tk.Frame(parent_frame, bg="#f4f6f8")
    container.place(relx=0.5, rely=0.5, anchor="center")
    tk.Label(parent_frame, text="Вітаємо у RzeczFlex!",
             font=("Montserrat", 20, "bold"), bg="#f4f6f8") \
        .pack(pady=(60, 30))
    tk.Button(parent_frame, text="Вхід", command=open_login_window,
              width=20, height=2, bg="#A3EEFF", fg="black", font=("Montserrat", 16)) \
        .pack(pady=(0, 20))
    tk.Button(parent_frame, text="Реєстрація", command=open_register_window,
              width=20, height=2, bg="#C3E7EF", fg="black", font=("Montserrat", 16)) \
        .pack()
create_selection_frame_content(selection_frame)
selection_frame.pack(expand=True, fill=tk.BOTH)
def on_root_close():
    if messagebox.askokcancel("Вихід", "Ви впевнені, що хочете закрити програму?", parent=root):
        if 'users_conn' in globals() and users_conn:
            users_conn.close()
        if 'pol_conn' in globals() and pol_conn:
            pol_conn.close()
        root.destroy()

root.protocol("WM_DELETE_WINDOW", on_root_close)
try:
    root.mainloop()
except KeyboardInterrupt:
    if 'users_conn' in globals() and users_conn:
        users_conn.close()
    if 'pol_conn' in globals() and pol_conn:
        pol_conn.close()
    root.destroy()

