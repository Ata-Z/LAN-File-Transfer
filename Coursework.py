from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit, QMessageBox, QTextEdit, QSystemTrayIcon
from PyQt5.QtGui import QDragEnterEvent, QDropEvent, QDragLeaveEvent, QIcon
from PyQt5.QtCore import Qt
import os
import sys
import hashlib
import json
import socket
import hmac
import time
import winsound
import getpass
import shutil

app = QApplication([])

def RoleSelectGUI():
     # Assigns QApplication to be used in app variable, handles GUI initialisation

    role_window = QWidget() # Creates a main window for the RoleSelectGUI, allowing attribute customization as well

    role_window.setWindowTitle("Select Role") # Sets the title of the window
    role_window.setGeometry(100, 100, 300, 200) # Sets the size of the window

    admin_button = QPushButton("Admin", role_window) # Assigns the button to role_window, the widget
    client_button = QPushButton("Client", role_window)

    layout = QVBoxLayout()
    role_window.setLayout(layout) # Assigns the QVBoxlayout to the window
    layout.addWidget(admin_button)
    layout.addWidget(client_button)

    def select_client():
        global selected_role
        selected_role = "client"
        role_window.close()
    def select_admin():
        global selected_role
        selected_role = "admin"
        role_window.close()

    client_button.clicked.connect(select_client)
    admin_button.clicked.connect(select_admin)

    role_window.show() # Displays the GUI on the screen

    app.exec() # Runs event loop of the GUI

    return selected_role


if not os.path.exists("role"): # Checks if the file 'role' exists in the programs directory
    selected_role = RoleSelectGUI() # makes selected_role equal to what role is returned by the function
    with open("role","w") as file:
        file.write(selected_role) # Writes the role to the file

def LoginGUI():
    login_window = QWidget()
    login_window.setWindowTitle("Admin Login")
    login_window.setGeometry(100, 100, 300, 200)
    layout = QVBoxLayout()

    username_input = QLineEdit(login_window) # Users will be able to write in this
    password_input = QLineEdit(login_window)
    password_input.setEchoMode(QLineEdit.Password) # Sets the writeable user line to be in 'password mode', this will hide whats written

    layout.addWidget(QLabel("Username"))
    layout.addWidget(username_input)
    layout.addWidget(QLabel("Password"))
    layout.addWidget(password_input)

    submit_button = QPushButton("Submit", login_window)

    inputted_userpass = ["", ""] # A list that will hold the submitted username and password

    def on_submit(): # Grabs the values stored in the text boxes, and stores them inside the list 'inputted_userpass'
        inputted_userpass[0] = username_input.text()
        inputted_userpass[1] = password_input.text()
        login_window.close()  # Close the login window

    submit_button.clicked.connect(on_submit) # When submit is clicked, on_submit() will run
    layout.addWidget(submit_button)

    login_window.setLayout(layout)
    login_window.show()

    while login_window.isVisible(): # Will stop it from looping until the window is no longer visible, removes need for app
        QApplication.processEvents()

    return inputted_userpass[0], inputted_userpass[1]

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest() # Uses SHA256 Hashing Algorithm to encode the password, and then returns it
# string format using hexdigest()

if not os.path.exists("login"): # If Login file doesn't exist get username and password returned from LoginGUI's list
    username, password = LoginGUI()
    hashed_password = hash_password(password)
    with open("login", "w") as f:
        f.write(f"{username}\n{hashed_password}") # Writes the username and password in seperate lines to the file

def play_success_sound():
            sound_file = "success.wav"
            winsound.PlaySound(sound_file, winsound.SND_FILENAME)

def play_error_sound():
            sound_file = "error.wav"
            winsound.PlaySound(sound_file, winsound.SND_FILENAME)

class FileTransferApp: # Most of the program will be in this class as a lot of the parts will rely on each other
    def __init__(self):
        self.app = app
        
        with open("role", "r") as file:
            self.role = file.read()
            if self.role == "admin":
                self.check_login()
                self.admin_GUI() # Currently doesnt exist MAKE SURE THIS DOESNT SAY SELF, TILL AFTER THE TEST
            elif self.role == "client":
                self.client_startup()
    def check_login(self):
        while True: # This will cause it to loop until the user inputs the same credentials as the one stored in the file
            self.submitted_username, self.submitted_password = LoginGUI()
            if not self.submitted_username or not self.submitted_password:
                # If the user cancels the login dialog, exit the program
                QMessageBox.warning(None, "Login Canceled", "Login process was canceled.")
                exit()

            with open("login", "r") as f: # Opens the login file in read mode
                lines = f.readlines() # stores the data of the two lines of 'login' in the variable 'lines' 
                login_data = {
                    "username": lines[0].strip(),
                    "password": lines[1].strip() # The username and password are set as elements of the dictionary 'login_data'
                }

            hashed_submitted_password = hash_password(self.submitted_password)
            if self.submitted_username == login_data["username"] and hashed_submitted_password == login_data["password"]:
                break # Breaks when submitted data matches the data in the dictionary
            else:
                QMessageBox.warning(None, "Login Failed", "Incorrect username or password.") # Show an error message if credentials incorrect
                continue # If it doesnt match, the loop restarts, the login GUI reloads, and clears its elements

    def admin_GUI(self):
        self.admin_window = QWidget()
        self.admin_window.setWindowTitle("Admin Window")
        self.admin_window.setGeometry(100, 100, 400, 300)
        self.admin_window.showMaximized() # Will ignore the geometry of the window, and display it maximised

        self.admin_window.setAcceptDrops(True) # Window will accept things like file drops

        main_layout = QVBoxLayout()
        self.admin_window.setLayout(main_layout) # Assigning QVBoxLayout as the main layout of window

        top_layout = QHBoxLayout()
        main_layout.addLayout(top_layout) # Assigning QHBoxLayout as another layout, will allow me to place things in horizontal order

        top_layout.addStretch() # Spaces my widgets and icons to be on the right side of the GUI

        settings_button = QPushButton()
        settings_button.setIcon(QIcon("settings.png")) # Assigns settings.png to display on settings_button as an icon
        settings_button.setFixedSize(40, 40) # Decide the size of the button
        top_layout.addWidget(settings_button)
        settings_button.clicked.connect(self.open_settings) # Doesn't exist yet

        center_layout = QVBoxLayout()
        main_layout.addLayout(center_layout)
        center_layout.addStretch() # Further formatting the positioning of widgets etc

        label = QLabel("Drag and Drop files here", self.admin_window)
        label.setAlignment(Qt.AlignCenter) # Places label in the center of the screen
        center_layout.addWidget(label)

        center_layout.addStretch() # Pushes my button downward

        submit = QPushButton("Submit", self.admin_window)
        center_layout.addWidget(submit)
        submit.clicked.connect(self.send_files) # Doesn't exist right now

        self.admin_window.setObjectName("AdminWindow")

        def drag_enter_event(event: QDragEnterEvent): # Makes the event of this function QDragEnterEvent
            if event.mimeData().hasUrls(): # mimeData retrieves the data assosciated with drag operation, hasUrls checks if it has urls,
                event.accept() #             like file paths, if this is the case, then accept that drag event
                self.admin_window.setStyleSheet("#AdminWindow { border: 5px solid blue; }") # Change the border of the admin window to blue
            else:
                event.ignore()

        def drag_leave_event(event: QDragLeaveEvent):
            self.admin_window.setStyleSheet("") # Reset border when dragged item leaves the window

        def drop_event(event: QDropEvent):
            if event.mimeData().hasUrls():
                urls = event.mimeData().urls() # Retrieve the URLs and store them in 'urls'
                if not hasattr(self, "file_paths"): # check if file_paths exists as an attribute in this instance, if not, make it
                    self.file_paths = []
                new_file_paths = [url.toLocalFile() for url in urls] # Convert the QUrl objects to file paths and store them in the var
                self.file_paths.extend(new_file_paths) # Add the new file paths file_paths, extend used as multiple at a time
                file_names = [os.path.basename(path) for path in new_file_paths] # Get the names of the files dropped
                current_text = label.text()
                if current_text == "Drag and Drop files here": # After a file's dropped if label says the default thing, clear it
                    current_text = ""
                new_text = "\n".join(file_names) # Join the file names into a single string, seperated by a new line each time
                updated_text = current_text + "\n" + new_text if current_text else new_text # Join the new text with the current text
                label.setText(updated_text) # Display the updated texts
                print(self.file_paths)

            self.admin_window.setStyleSheet("") # Reset the border/whole stylesheet back to default after file dropped

        self.admin_window.dragEnterEvent = drag_enter_event # Assigns the dragEnterEvent of this window to be handled by the function
        self.admin_window.dragLeaveEvent = drag_leave_event
        self.admin_window.dropEvent = drop_event


        self.admin_window.show()

    def send_files(self):
        settings = self.load_settings() # Stores settings json data in settings dictionary
        multicast_address = settings["multicast_address"] # Stores the value assosciated with multicast_address in json
        port_number = settings["port_number"]
        chunk_size = settings["chunk_size"]
        transmission_rate = settings["transmission_rate"]

        print(f"Multicast Address: {multicast_address}")
        print(f"Port Number: {port_number}")
        print(f"Chunk Size: {chunk_size}")
        print(f"Transmission Rate: {transmission_rate}")

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) # sock is defined to be an IPv4 socket which is datagram based, (UDP)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2) # Modifiying the sockets settings, the TTL is set to 2

        try:
            for file_path in self.file_paths: # Will do this process for each file
                try:
                    with open(file_path, "rb") as file:
                        file_size = os.path.getsize(file_path) # Stores the file size
                        file_name = os.path.basename(file_path) # Stores the file name

                        # Send metadata
                        metadata_packet = f"FILE:{file_name}:{file_size}".encode("utf-8") # Stores file size and name in metadata
                        sock.sendto(metadata_packet, (multicast_address,port_number)) # metadata packet sent on the soekcet
                        time.sleep(1 / transmission_rate)

                        # Send file chunks
                        while chunk := file.read(chunk_size): # Reads a chunk of file and stores it, if EOF, will return an empty string
                            sock.sendto(chunk, (multicast_address,port_number)) # Packet sent on socket
                            time.sleep(1 / transmission_rate)

                        # Send FILE_END signal when loop breaks i.e. No more packets left to send
                        file_end_metadata = f"FILE_END:{file_name}:{file_size}".encode("utf-8")
                        sock.sendto(file_end_metadata, (multicast_address,port_number))
                        time.sleep(1 / transmission_rate)

                        print(f"File sent successfully: {file_path}")
                        play_success_sound()

                except FileNotFoundError:
                    print(f"File not found: {file_path}")
                    play_error_sound()

        except Exception as e:
            print(f"Error during file transfer: {e}")
            play_error_sound()
        finally:
            sock.close()

    def settings_GUI(self):
        self.settings_window = QWidget()
        self.settings_window.setWindowTitle("Settings")
        self.settings_window.setGeometry(100, 100, 600, 400)
        self.settings_window.showMaximized()

        self.settings = self.load_settings()

        output_layout = QVBoxLayout()
        self.settings_window.setLayout(output_layout)

        settings_layout = QVBoxLayout()
        output_layout.addLayout(settings_layout)

        log_output = QTextEdit() # A text box in which all outputs and errors of the program will be displayed
        log_output.setReadOnly(True) # Make it unwriteable
        output_layout.addWidget(log_output)

        multicast_label = QLabel("Multicast Address:")
        self.multicast_input = QLineEdit(self.settings_window)
        self.multicast_input.setPlaceholderText("Enter Multicast Address (e.g., 224.0.0.1)") # Placeholder text when nothings written
        self.multicast_input.setText(self.settings["multicast_address"]) # Grabs multicast_address value from settings json - doesn't exist yet
        settings_layout.addWidget(multicast_label)
        settings_layout.addWidget(self.multicast_input)

        port_label = QLabel("Port Number:")
        self.port_input = QLineEdit(self.settings_window)
        self.port_input.setPlaceholderText("Enter Port Number (e.g., 5000)")
        self.port_input.setText(str(self.settings["port_number"]))
        settings_layout.addWidget(port_label)
        settings_layout.addWidget(self.port_input)

        chunk_size_label = QLabel("Chunk Size (bytes):")
        self.chunk_size_input = QLineEdit(self.settings_window)
        self.chunk_size_input.setPlaceholderText("Enter Chunk Size (e.g., 1024)")
        self.chunk_size_input.setText(str(self.settings["chunk_size"]))
        settings_layout.addWidget(chunk_size_label)
        settings_layout.addWidget(self.chunk_size_input)

        transmission_rate_label = QLabel("Transmission Rate (packets/second):")
        self.transmission_rate_input = QLineEdit(self.settings_window)
        self.transmission_rate_input.setPlaceholderText("Enter Transmission Rate")
        self.transmission_rate_input.setText(str(self.settings["transmission_rate"]))
        settings_layout.addWidget(transmission_rate_label)
        settings_layout.addWidget(self.transmission_rate_input)

        save_button = QPushButton("Save Settings")
        settings_layout.addWidget(save_button)
        save_button.clicked.connect(self.save_settings) # Not defined yet

        back_button = QPushButton("Back")
        output_layout.addWidget(back_button)
        if self.role == "admin":
            back_button.clicked.connect(self.open_admin) # Not defined yet, will open admin window and close settings window
        else:
            back_button.clicked.connect(self.close_settings_window) # Not defined yet, if their role is not admin, it will just close
#                                                                     settings window
        class LogRedirector:
            def write(self, text):
                log_output.append(text.strip())

            def flush(self):
                pass

        sys.stdout = LogRedirector()
        sys.stderr = LogRedirector()

    def open_settings(self):
        if self.role == "admin":
            self.admin_window.hide()
        elif self.role == "client":
            pass # Will do clients version when I program clientside  --- WHAT? I THINK THIS NEEDS TO BE REMOVED, CLIENT NOT SPECIAL THING
        self.settings_GUI()

    def open_admin(self):
        self.settings_window.hide()
        self.admin_GUI()

    def close_settings_window(self):
        self.settings_window.close()

    def save_settings(self):
        try:
            self.settings["multicast_address"] = self.multicast_input.text() # Assigns the value of multicast_address from text of box
            self.settings["port_number"] = int(self.port_input.text())
            self.settings["chunk_size"] = int(self.chunk_size_input.text())
            self.settings["transmission_rate"] = int(self.transmission_rate_input.text())

            with open("settings.json", "w") as file:
                json.dump(self.settings, file, indent=4) # Formats it to json and adds an indent of 4 for readibility
            print("Settings saved:", self.settings) # Prints the settings that were added to the 
        except Exception as e:
            print("Error saving settings:", e)

    def load_settings(self): # Function to load grab settings from a json file
            default_settings = {
                "multicast_address": "224.1.1.1",
                "port_number": 5000,
                "chunk_size": 1024,
                "transmission_rate": 10
            }

            try:
                with open("settings.json", "r") as file:
                    settings = json.load(file)
                    print("Settings loaded:", settings)
                    return settings
            except (FileNotFoundError, json.JSONDecodeError): # If the file doesn't exist, or it failed to decode, then default settings
                with open("settings.json", "w") as file:
                    json.dump(default_settings, file, indent=4) # Writes default settings to file
                print("Default settings created:", default_settings)
                return default_settings
    
    def client_startup(self):
        check_startup()
        self.client_GUI()
        

    def client_GUI(self):
        self.tray_icon = QSystemTrayIcon(QIcon("settings.png"), self.app) # Adding an icon in the tray with settings.png as icon
        self.tray_icon.setToolTip("Client Background Service") # This is its name
        self.tray_icon.activated.connect(self.tray_icon_clicked) # when clicked it will run tray_icon_clicked()
        self.tray_icon.show() # Displays it in tray

    def tray_icon_clicked(self, reason):
        if reason == QSystemTrayIcon.Trigger: # if the reason of interaction was a left click
            self.check_login() # load the check login function to load loginGUI()
            self.open_settings() # Once logged in, it will open settings


    def receive_files(self):
        settings = self.load_settings()
        multicast_address = settings["multicast_address"]
        port_number = settings["port_number"]
        chunk_size = settings["chunk_size"]
        save_directory = os.path.join(os.path.expanduser("~"), "Downloads")

        # Set up the multicast socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((multicast_address, port_number))
        mreq = socket.inet_aton(multicast_address) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print(f"Listening for files on {multicast_address}:{port_number}...")

        try:
            while True:
                # Receive metadata packet
                metadata, _ = sock.recvfrom(chunk_size)
                metadata = metadata.decode("utf-8")

                # Check if it's a FILE or FILE_END packet
                if metadata.startswith("FILE:"):
                    _, file_name, file_size = metadata.split(":", 2)
                    file_size = int(file_size)
                    print(f"Receiving file: {file_name} ({file_size} bytes)")

                    # Prepare to receive file chunks
                    file_path = os.path.join(save_directory, file_name)
                    received_data = b""  # Store all received chunks here

                    while True:
                        # Receive a chunk
                        chunk, _ = sock.recvfrom(chunk_size)
                        chunk_str = chunk.decode("utf-8")

                        # Check if it's a FILE_END packet
                        if chunk_str.startswith("FILE_END:"):
                            # Save the received data to a file
                            with open(file_path, "wb") as file:
                                file.write(received_data)
                            print(f"File received and saved: {file_path}")
                            break

                        # Append the chunk to the received data
                        received_data += chunk

        except KeyboardInterrupt:
            print("File reception stopped by user.")
        except Exception as e:
            print(f"Error receiving files: {e}")
        finally:
            sock.close()
        
    def run(self):
        self.app.exec_()
            
def check_startup():
    # This would just be file transfer.exe in the real program, dist for testing as thats the file path when compiled with pyinstaller
    exe_path = os.path.abspath("dist//File Transfer.exe")
    user = getpass.getuser() # Gets the username of the client's computer account running the program
    startup_folder = f"C://Users//{user}//AppData//Roaming//Microsoft//Windows//Start Menu//Programs//Startup" # Startup folder directory
    destination_path = os.path.join(startup_folder, "File Transfer.exe") # Folder directory + program name

    if not os.path.exists(destination_path): # If program in the folder doesnt exist, run this
        print("File Transfer is not set to run at startup. Adding it now...")
        try:
            shutil.copy(exe_path, destination_path) # Copies the file to the new location
            print(f"Copied {exe_path} to startup folder.")
        except Exception as e:
            print(f"Failed to add to startup: {e}")
    else:
        print("File Transfer is already set to run at startup.")



app = FileTransferApp()
app.run()
