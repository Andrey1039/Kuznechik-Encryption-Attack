using System;
using System.Linq.Expressions;
using System.Text;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using Kuznechik_Encryption.Data;
using Kuznechik_Encryption.Encryption;
using static System.Net.Mime.MediaTypeNames;

namespace Kuznechik_Encryption
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            InstallParams();
            Encoding.RegisterProvider(CodePagesEncodingProvider.Instance);
        }

        private void InstallParams()
        {
            InputTextTB.Text = "qwertyuiopasdfgh";
            InputKeyTB.Text = "123456789ghtrewsdcvbnmkjhgfdsazx";
        }

        private void InputData_TextChanged(object sender, TextChangedEventArgs e)
        {
            if (InputTextTB.Text.Equals(string.Empty) || InputKeyTB.Text.Length != 32)
                AttackBtn.IsEnabled = false;
            else
                AttackBtn.IsEnabled = true;
        }

        private void AttackBtn_Click(object sender, RoutedEventArgs e)
        {
            Kuznechik message = new Kuznechik();
            byte[] resultKey = new byte[32];

            for (int round = 0; round < 2; round++)
            {
                byte[] inputText = Encoding.GetEncoding(1251).GetBytes(InputTextTB.Text);

                for (int numberByte = 0; numberByte < 16; numberByte++)
                    for (int symbol = 0; symbol < 256; symbol++)
                    {
                        inputText[numberByte] = (byte)symbol;
                        string modInputText = Encoding.GetEncoding(1251).GetString(inputText);
                    
                        string originalResult = message.Encryption(modInputText, InputKeyTB.Text, true, round, numberByte);
                        string modResult = message.Encryption(modInputText, InputKeyTB.Text, false, round, numberByte);

                        if (originalResult == modResult)
                        {
                            if (round == 0)
                            {
                                resultKey[numberByte] = ConversionTables.Pi_Reverse[0];
                                resultKey[numberByte] = (byte)(resultKey[numberByte] ^ inputText[numberByte]);
                            }
                            else
                            {
                                byte[] secondRoundText = message.X(inputText, resultKey);
                                secondRoundText = message.S(secondRoundText, true);
                                secondRoundText = message.L(secondRoundText);

                                resultKey[numberByte + 16] = ConversionTables.Pi_Reverse[0];
                                resultKey[numberByte + 16] = (byte)(resultKey[numberByte + 16] ^ secondRoundText[numberByte]);
                            }
                        }
                    }
            }

            FoundedKeyTB.Text = Encoding.GetEncoding(1251).GetString(resultKey);
            ResultLB.Content = FoundedKeyTB.Text == InputKeyTB.Text ? "да" : "нет";               
        }     
    }
}
