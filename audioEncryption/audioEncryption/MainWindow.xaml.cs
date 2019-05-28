using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace AudioEncryption
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window, INotifyPropertyChanged
    {
        WavFile data = new WavFile();
        private string originalWavPath;
        private string statusString = "brak";
        private string statusAdditionalInfo;
        private string commonKeyFileNamePart;
        private string uniqueKeyFileNamePart;

        public string OriginalWavPath
        {
            get
            {
                return originalWavPath;
            }
            set
            {
                if (originalWavPath != value)
                {
                    originalWavPath = value;
                    OnPropertyChanged();
                }
            }
        }

        public string StatusString
        {
            get
            {
                return statusString;
            }
            private set
            {
                if (statusString != value)
                {
                    statusString = value;
                    OnPropertyChanged();
                }
            }
        }

        public string StatusAdditionalInfo
        {
            get
            {
                return statusAdditionalInfo;
            }
            set
            {
                statusAdditionalInfo = " " + value;
                OnPropertyChanged();
            }
        }

        public string CommonKeyFileNamePart
        {
            get
            {
                return commonKeyFileNamePart;
            }
            set
            {
                commonKeyFileNamePart = value + ".txt";
                OnPropertyChanged();
            }
        }

        public string UniqueKeyFileNamePart
        {
            get
            {
                return uniqueKeyFileNamePart;
            }
            set
            {
                uniqueKeyFileNamePart = value;
                OnPropertyChanged();
            }
        }


        public MainWindow()
        {
            DataContext = this;
            InitializeComponent();
        }


        private void PickWavButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog wavOpenDialog = new OpenFileDialog();
            wavOpenDialog.Title = "Wybierz plik wav";
            wavOpenDialog.Filter = "Plik wav|*.wav";

            if (wavOpenDialog.ShowDialog() == true)
            {
                OriginalWavPath = wavOpenDialog.FileName;
            }
        }

        private void LoadWavButton_Click(object sender, RoutedEventArgs e)
        {
            if (!data.LoadDataFromFile(OriginalWavPath))
                Console.WriteLine("Loading data from file failed. File not found.");
            else
            {
                MetadataTextBlock.Text = data.GetMetadataString();
                if (data.Status == WavFileState.Loaded)
                {
                    StatusString = "załadowany";
                    StatusAdditionalInfo = "";
                    CommonKeyFileNamePart = data.FileName.Replace(".wav", "");
                }
            }
        }

        public event PropertyChangedEventHandler PropertyChanged;
        public void OnPropertyChanged([CallerMemberName] string propertyName = null)
        {
            PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(propertyName));
        }

        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!data.Encrypt())
            {
                if (data.Status == WavFileState.Empty)
                    StatusAdditionalInfo = "(błąd szyfrowania - nie załadowano pliku)";
                if (data.Status == WavFileState.Loaded || data.Status == WavFileState.Decrypted)
                    StatusAdditionalInfo = "(błąd szyfrowania - nie ustawiono klucza publicznego)";
                if (data.Status == WavFileState.Encrypted)
                    StatusAdditionalInfo = "(błąd szyfrowania - plik już jest zaszyfrowany w tej sesji)";
            }
            else
            {
                if (data.Status == WavFileState.Encrypted)
                {
                    StatusString = "zaszyfrowany";
                    StatusAdditionalInfo = "(niezapisany)";
                }
            }
        }

        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            if (!data.Decrypt())
            {
                if (data.Status == WavFileState.Empty)
                    StatusAdditionalInfo = "(błąd deszyfrowania - nie załadowano pliku)";
                if (data.Status == WavFileState.Loaded || data.Status == WavFileState.Encrypted)
                    StatusAdditionalInfo = "(błąd deszyfrowania - nie ustawiono prawidłowego klucza prywatnego)";
                if (data.Status == WavFileState.Decrypted)
                    StatusAdditionalInfo = "(błąd deszyfrowania - plik został już odszyfrowany w tej sesji)";
            }
            else
            {
                if (data.Status == WavFileState.Decrypted)
                {
                    StatusString = "odszyfrowany";
                    StatusAdditionalInfo = "(niezapisany)";
                }
            }
        }

        private void SaveAsButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog wavSaveAsDialog = new SaveFileDialog();
            wavSaveAsDialog.Title = "Zapisz zmodyfikowany plik jako";
            wavSaveAsDialog.Filter = "Plik wav|*.wav";

            if (wavSaveAsDialog.ShowDialog() == true)
            {
                data.SaveToWavFile(wavSaveAsDialog.FileName);
                StatusAdditionalInfo = "(zapisany)";
            }
        }

        private void GenerateKeyParButton_Click(object sender, RoutedEventArgs e)
        {
            RsaManager.generateKeyPar();
            PrivateKeyTextBlock.Text = RsaManager.GetKeyString(true);
            PublicKeyTextBlock.Text = RsaManager.GetKeyString(false);
        }

        private void LoadPrivateKeyButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog OpenDialog = new OpenFileDialog();
            OpenDialog.Title = "Wybierz plik zawierający klucz prywatny";

            if (OpenDialog.ShowDialog() == true)
            {
                string privateKey = File.ReadAllText(OpenDialog.FileName, Encoding.UTF8);
                RsaManager.SetKey(true, privateKey);
                PrivateKeyTextBlock.Text = RsaManager.GetKeyString(true);
            }
        }

        private void PrivateKeySaveAsButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog SaveAsDialog = new SaveFileDialog();
            SaveAsDialog.Title = "Zapisz klucz prywatny jako";
            SaveAsDialog.Filter = "Plik tekstowy|*.txt";

            if (SaveAsDialog.ShowDialog() == true)
            {
                RsaManager.WriteKeysToFile(true, SaveAsDialog.FileName);
            }
        }

        private void LoadPublicKeyButton_Click(object sender, RoutedEventArgs e)
        {
            OpenFileDialog OpenDialog = new OpenFileDialog();
            OpenDialog.Title = "Wybierz plik zawierający klucz publiczny";

            if (OpenDialog.ShowDialog() == true)
            {
                string publicKey = File.ReadAllText(OpenDialog.FileName, Encoding.UTF8);
                RsaManager.SetKey(false, publicKey);
                PublicKeyTextBlock.Text = RsaManager.GetKeyString(false);
            }
        }

        private void PublicKeySaveAsButton_Click(object sender, RoutedEventArgs e)
        {
            SaveFileDialog SaveAsDialog = new SaveFileDialog();
            SaveAsDialog.Title = "Zapisz klucz publiczny jako";
            SaveAsDialog.Filter = "Plik tekstowy|*.txt";

            if (SaveAsDialog.ShowDialog() == true)
            {
                RsaManager.WriteKeysToFile(false, SaveAsDialog.FileName);
            }
        }

        private void SaveBothKeysButton_Click(object sender, RoutedEventArgs e)
        {
            var privateKeyName = UniqueKeyFileNamePart + "-private_key-" + CommonKeyFileNamePart;
            var publicKeyName = UniqueKeyFileNamePart + "-public_key-" + CommonKeyFileNamePart;

            RsaManager.WriteKeysToFile(privateKeyName, publicKeyName);

            string message = "Klucze zostały zapisane pod nazwami:\n\n" + privateKeyName + "\n" + publicKeyName;
            MessageBox.Show(message, "Zapisano", MessageBoxButton.OK, MessageBoxImage.Information);
        }
    }
}
