import tkinter
from tkinter import ttk
from tkinter import filedialog
from utils.tkinter_tooltip import CreateToolTip
from PIL import ImageTk
import sv_ttk
import tkinter.messagebox
from scripts import client_side, auditor_side, decrypt_result


def browse_button(folder_path):
    filename = filedialog.askdirectory()
    folder_path.set(filename)


def browse_file_button(file_path):
    filename = filedialog.askopenfilename()
    file_path.set(filename)


def show_button(entry: ttk.Entry, button: ttk.Button):
    if entry.cget("show") == "*":
        entry.config(show="")
        button.config(image=password_show_image)
    else:
        entry.config(show="*")
        button.config(image=password_hide_image)


root = tkinter.Tk()
root.title("MSAT")

password_show_image = ImageTk.PhotoImage(file="assets/eye_open2.png")
password_hide_image = ImageTk.PhotoImage(file="assets/eye_closed2.png")
folder_image = ImageTk.PhotoImage(file="assets/folder.png")
question_mark_image = ImageTk.PhotoImage(file="assets/question_mark.png")

tabControl = ttk.Notebook(root)
client_tab = ttk.Frame(tabControl)
auditor_tab = ttk.Frame(tabControl)
decrypt_tab = ttk.Frame(tabControl)

loading = tkinter.StringVar()

########################################################################################################################
#                                                       Client Side                                                    #
########################################################################################################################
client_side_frame = ttk.Frame(client_tab, borderwidth=10, padding=10)
client_side_tooltip_button = ttk.Button(client_side_frame, image=question_mark_image)
client_side_tooltip = CreateToolTip(client_side_tooltip_button,
                                    'This is the first step the client must take. \n\n'
                                    'Project Directory: The directory of the project you want to analyze. \n\n'
                                    'Secret Password: The password that will be used to encrypt the code. Only the project owner must know this password. \n\n'
                                    'Shared Password: The password that the tool will use to be able to detect vulnerabilities without revealing any code. \n\n'
                                    'Output Directory: The directory where the encrypted project will be saved.')
client_side_tooltip_button.place(in_=client_side_frame, relx=1.0, rely=0.0, anchor="ne")

client_side_umbrela = ttk.Label(client_side_frame, text="Encrypt your project for later analysis")
client_side_umbrela.grid(row=0, column=0, columnspan=3, padx=10, pady=15)

project_dir = tkinter.StringVar()
project_dir_label = ttk.Label(client_side_frame, text="Project Directory")
project_dir_label.grid(row=1, column=0, padx=10, pady=10, sticky="W")
project_dir_entry = ttk.Entry(client_side_frame, textvariable=project_dir)
project_dir_entry.grid(row=1, column=1, padx=10, pady=10, sticky="W")
project_dir_browse_button = ttk.Button(client_side_frame, image=folder_image,
                                       command=lambda: browse_button(project_dir))
project_dir_browse_button.grid(row=1, column=2, padx=10, pady=10, sticky="W")

client_secret_password = tkinter.StringVar()
client_secret_password_label = ttk.Label(client_side_frame, text="Secret Password")
client_secret_password_label.grid(row=2, column=0, padx=10, pady=10, sticky="W")
client_secret_password_entry = ttk.Entry(client_side_frame, show="*", textvariable=client_secret_password)
client_secret_password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="W")
client_secret_password_show_button = ttk.Button(client_side_frame, image=password_hide_image,
                                                command=lambda: show_button(client_secret_password_entry,
                                                                            client_secret_password_show_button))
client_secret_password_show_button.grid(row=2, column=2, padx=10, pady=10, sticky="W")
client_side_frame.grid(pady=20, padx=20)

client_shared_password = tkinter.StringVar()
client_shared_password_label = ttk.Label(client_side_frame, text="Shared Password")
client_shared_password_label.grid(row=3, column=0, padx=10, pady=10, sticky="W")
client_shared_password_entry = ttk.Entry(client_side_frame, show="*", textvariable=client_shared_password)
client_shared_password_entry.grid(row=3, column=1, padx=10, pady=10, sticky="W")
client_shared_password_show_button = ttk.Button(client_side_frame, image=password_hide_image,
                                                command=lambda: show_button(client_shared_password_entry,
                                                                            client_shared_password_show_button))
client_shared_password_show_button.grid(row=3, column=2, padx=10, pady=10, sticky="W")
client_side_frame.grid(pady=20, padx=20)

output_dir = tkinter.StringVar()
output_dir_label = ttk.Label(client_side_frame, text="Output Directory")
output_dir_label.grid(row=4, column=0, padx=10, pady=10, sticky="W")
output_dir_entry = ttk.Entry(client_side_frame, textvariable=output_dir)
output_dir_entry.grid(row=4, column=1, padx=10, pady=10, sticky="W")
output_dir_browse_button = ttk.Button(client_side_frame, image=folder_image, command=lambda: browse_button(output_dir))
output_dir_browse_button.grid(row=4, column=2, padx=10, pady=10, sticky="W")

client_execute_button = ttk.Button(client_side_frame, text="Execute", command=lambda: client_side_execute(
    client_secret_password.get(), client_shared_password.get(), project_dir.get(), output_dir.get()))
client_execute_button.grid(row=5, column=0, columnspan=3, pady=20)


def client_side_execute(secret_password, shared_password, project_dir, output_dir):
    loading.set("Loading...")
    root.update()
    if not project_dir:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Project Directory is required.")
        return
    if not secret_password:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Secret Password is required.")
        return
    if not shared_password:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Shared Password is required.")
        return
    if not output_dir:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Output Directory is required.")
        return

    result = client_side.main(secret_password, shared_password, project_dir, output_dir)
    loading.set("")
    root.update()
    if result[0]:
        tkinter.messagebox.showinfo("Success", result[1])
    else:
        tkinter.messagebox.showerror("Error", result[1])


client_side_loading = ttk.Label(client_side_frame, textvariable=loading)
client_side_loading.grid(row=6, column=0, columnspan=3, pady=20)
client_side_frame.pack(pady=20, padx=20)

########################################################################################################################
#                                                      Auditor Side                                                    #
########################################################################################################################
auditor_side_frame = ttk.Frame(auditor_tab, borderwidth=10, padding=10)
auditor_side_tooltip_button = ttk.Button(auditor_side_frame, image=question_mark_image)
auditor_side_tooltip = CreateToolTip(auditor_side_tooltip_button,
                                     'This is where the vulnerabilities are detected but not revealed. \n\n'
                                     'Shared Password: The password that allows for vulnerability detection without revealing them. \n\n'
                                     'Encrypted Code Path: The path to the encrypted code file. \n\n'
                                     'Vulnerability to detect: The type of vulnerability to detect. \n\n'
                                     'Result Directory: The directory where the encrypted result will be saved.')
auditor_side_tooltip_button.place(in_=auditor_side_frame, relx=1.0, rely=0.0, anchor="ne")

auditor_side_umbrela = ttk.Label(auditor_side_frame, text="Detect vulnerabilities without revealing them")
auditor_side_umbrela.grid(row=0, column=0, columnspan=3, padx=10, pady=15)

auditor_shared_password = tkinter.StringVar()
auditor_shared_password_label = ttk.Label(auditor_side_frame, text="Shared Password")
auditor_shared_password_label.grid(row=1, column=0, padx=10, pady=10, sticky="W")
auditor_shared_password_entry = ttk.Entry(auditor_side_frame, show="*", textvariable=auditor_shared_password)
auditor_shared_password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="W")
auditor_shared_password_show_button = ttk.Button(auditor_side_frame, image=password_hide_image,
                                                 command=lambda: show_button(auditor_shared_password_entry,
                                                                             auditor_shared_password_show_button))
auditor_shared_password_show_button.grid(row=1, column=2, padx=10, pady=10, sticky="W")
auditor_side_frame.grid(pady=20, padx=20)

encrypted_code_path = tkinter.StringVar()
encrypted_code_path_label = ttk.Label(auditor_side_frame, text="Encrypted Code Path")
encrypted_code_path_label.grid(row=2, column=0, padx=10, pady=10, sticky="W")
encrypted_code_path_entry = ttk.Entry(auditor_side_frame, textvariable=encrypted_code_path)
encrypted_code_path_entry.grid(row=2, column=1, padx=10, pady=10, sticky="W")
encrypted_code_path_browse_button = ttk.Button(auditor_side_frame, image=folder_image,
                                               command=lambda: browse_file_button(encrypted_code_path))
encrypted_code_path_browse_button.grid(row=2, column=2, padx=10, pady=10, sticky="W")

vulnerability_to_detect = tkinter.StringVar()
vulnerability_to_detect_label = ttk.Label(auditor_side_frame, text="Vulnerability to detect")
vulnerability_to_detect_label.grid(row=3, column=0, padx=10, pady=10, sticky="E")
xss_radio_button = ttk.Radiobutton(auditor_side_frame, text="XSS", variable=vulnerability_to_detect, value="XSS")
xss_radio_button.grid(row=3, column=1, padx=10, pady=10, sticky="")
sqli_radio_button = ttk.Radiobutton(auditor_side_frame, text="SQLI", variable=vulnerability_to_detect, value="SQLI")
sqli_radio_button.grid(row=3, column=2, padx=10, pady=10, sticky="W")

result_dir = tkinter.StringVar()
result_dir_label = ttk.Label(auditor_side_frame, text="Result Directory")
result_dir_label.grid(row=4, column=0, padx=10, pady=10, sticky="W")
result_dir_entry = ttk.Entry(auditor_side_frame, textvariable=result_dir)
result_dir_entry.grid(row=4, column=1, padx=10, pady=10, sticky="W")
result_dir_browse_button = ttk.Button(auditor_side_frame, image=folder_image, command=lambda: browse_button(result_dir))
result_dir_browse_button.grid(row=4, column=2, padx=10, pady=10, sticky="W")

auditor_execute_button = ttk.Button(auditor_side_frame, text="Execute", command=lambda: auditor_side_execute(
    auditor_shared_password.get(), encrypted_code_path.get(), vulnerability_to_detect.get(), result_dir.get()))
auditor_execute_button.grid(row=5, column=0, columnspan=3, pady=20)


def auditor_side_execute(shared_password, encrypted_code_path, vulnerability_to_detect, result_dir):
    loading.set("Loading...")
    root.update()
    if not shared_password:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Shared Password is required.")
        return
    if not encrypted_code_path:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Encrypted Code Path is required.")
        return
    if not vulnerability_to_detect:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Vulnerability to detect is required.")
        return
    if not result_dir:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Result Directory is required.")
        return

    result = auditor_side.main(shared_password, encrypted_code_path, vulnerability_to_detect, result_dir)
    loading.set("")
    root.update()
    if result[0]:
        tkinter.messagebox.showinfo("Success", result[1])
    else:
        tkinter.messagebox.showerror("Error", result[1])


auditor_side_loading = ttk.Label(auditor_side_frame, textvariable=loading)
auditor_side_loading.grid(row=6, column=0, columnspan=3, pady=20)
auditor_side_frame.pack(pady=20, padx=20)

########################################################################################################################
#                                                        Decrypt                                                       #
########################################################################################################################
decrypt_frame = ttk.Frame(decrypt_tab, borderwidth=10, padding=10)
decrypt_tooltip_button = ttk.Button(decrypt_frame, image=question_mark_image, )
decrypt_tooltip = CreateToolTip(decrypt_tooltip_button, \
                                'This is the last step the client takes. \n\n'
                                'Secret Password: The password that was used to encrypt the code. Only the project owner must know this password. \n\n'
                                'Shared Password: The password that the tool used to detect vulnerabilities without revealing any code. \n\n'
                                'Result file path: Path containing the encrypted result file.')
decrypt_tooltip_button.place(in_=decrypt_frame, relx=1.0, rely=0.0, anchor="ne")

decrypt_umbrela = ttk.Label(decrypt_frame, text="Decrypt result returned by the auditor side")
decrypt_umbrela.grid(row=0, column=0, columnspan=3, padx=10, pady=15)

decrypt_secret_password = tkinter.StringVar()
decrypt_secret_password_label = ttk.Label(decrypt_frame, text="Secret Password")
decrypt_secret_password_label.grid(row=1, column=0, padx=10, pady=10, sticky="W")
decrypt_secret_password_entry = ttk.Entry(decrypt_frame, show="*", textvariable=decrypt_secret_password)
decrypt_secret_password_entry.grid(row=1, column=1, padx=10, pady=10, sticky="W")
decrypt_secret_password_show_button = ttk.Button(decrypt_frame, image=password_hide_image,
                                                 command=lambda: show_button(decrypt_secret_password_entry,
                                                                             decrypt_secret_password_show_button))
decrypt_secret_password_show_button.grid(row=1, column=2, padx=10, pady=10, sticky="W")
decrypt_frame.grid(pady=20, padx=20)

decrypt_shared_password = tkinter.StringVar()
decrypt_shared_password_label = ttk.Label(decrypt_frame, text="Shared Password")
decrypt_shared_password_label.grid(row=2, column=0, padx=10, pady=10, sticky="W")
decrypt_shared_password_entry = ttk.Entry(decrypt_frame, show="*", textvariable=decrypt_shared_password)
decrypt_shared_password_entry.grid(row=2, column=1, padx=10, pady=10, sticky="W")
decrypt_shared_password_show_button = ttk.Button(decrypt_frame, image=password_hide_image,
                                                 command=lambda: show_button(decrypt_shared_password_entry,
                                                                             decrypt_shared_password_show_button))
decrypt_shared_password_show_button.grid(row=2, column=2, padx=10, pady=10, sticky="W")
decrypt_frame.grid(pady=20, padx=20)

result_path = tkinter.StringVar()
result_path_label = ttk.Label(decrypt_frame, text="Result file path")
result_path_label.grid(row=3, column=0, padx=10, pady=10, sticky="W")
result_path_entry = ttk.Entry(decrypt_frame, textvariable=result_path)
result_path_entry.grid(row=3, column=1, padx=10, pady=10, sticky="W")
result_path_browse_button = ttk.Button(decrypt_frame, image=folder_image,
                                       command=lambda: browse_file_button(result_path))
result_path_browse_button.grid(row=3, column=2, padx=10, pady=10, sticky="W")
decrypt_frame.pack(pady=20, padx=20)

decrypt_execute_button = ttk.Button(decrypt_frame, text="Execute", command=lambda: decrypt_execute(
    decrypt_secret_password.get(), decrypt_shared_password.get(), result_path.get()))


def decrypt_execute(decrypt_secret_password, decrypt_shared_password, result_path):
    loading.set("Loading...")
    root.update()
    if not decrypt_secret_password:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Secret Password is required.")
        return
    if not decrypt_shared_password:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Shared Password is required.")
        return
    if not result_path:
        loading.set("")
        tkinter.messagebox.showerror("Error", "Result file path is required.")
        return


    result = decrypt_result.main(decrypt_secret_password, decrypt_shared_password, result_path)
    loading.set("")
    root.update()
    if result[0]:
        decrypted_frame = tkinter.Toplevel(root)
        decrypted_frame.title("Decrypted Result")

        h = ttk.Scrollbar(decrypted_frame, orient='horizontal')

        h.pack(side="bottom", fill="x")

        v = ttk.Scrollbar(decrypted_frame)

        v.pack(side="right", fill="y")
        result_paths = result[1]
        text_widget = tkinter.Text(decrypted_frame, wrap="word", font="Arial 12", padx=10, pady=10)
        text_widget.pack(side="left", fill="both", expand=True)
        text_widget.insert("1.0", result[1])
        text_widget.config(yscrollcommand=v.set, xscrollcommand=h.set)
    else:
        tkinter.messagebox.showerror("Error", result[1])


decrypt_loading = ttk.Label(decrypt_frame, textvariable=loading)
decrypt_execute_button.grid(row=5, column=0, columnspan=3, pady=20)

########################################################################################################################
#                                                        Main Loop                                                     #
########################################################################################################################

tabControl.add(client_tab, text="Client Side")
tabControl.add(auditor_tab, text="Auditor Side")
tabControl.add(decrypt_tab, text="Decrypt Result")
tabControl.pack(expand=1, fill="both")

sv_ttk.set_theme("dark")

root.mainloop()
