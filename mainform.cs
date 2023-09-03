using System;
using System.Collections.Generic;
using System.IO;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using System.Threading;
using Leaf.xNet;
using System.Text.RegularExpressions;
using System.Diagnostics;
using Newtonsoft.Json.Linq;

namespace ViperDehasher
{
    public partial class mainform : Form
    {
        static string Date = DateTime.Now.ToString("MM-dd-yyyy-hh-mm-ss").ToString();
        public static ReaderWriterLockSlim Lock = new ReaderWriterLockSlim();
        int hashsplit;
        int itemsplit;
        int progress;
        int yes; //lazy name sry :/ but its to know if the hash was found or not and it counts it :D

        int MD5;
        int DMD5;
        int SHA1;
        int SHA3;
        int SHA256;
        int SHA384;
        int SHA512;
        public mainform()
        {
            InitializeComponent();
            comboBox1.SelectedIndex = 0;
        }

        private void textBox1_TextChanged(object sender, EventArgs e)
        {

        }

        private void button1_Click(object sender, EventArgs e)
        {
            Clipboard.SetText(textBox2.Text);
        }

        private void button2_Click(object sender, EventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog
            {
                Filter = "Text Files (*.txt)|*.txt",
                Multiselect = false
            };
            if (openFileDialog.ShowDialog() == DialogResult.OK)
            {
                try
                {
                    textBox1.Lines = File.ReadAllLines(openFileDialog.FileName);
                }
                catch (Exception ex)
                {
                    MessageBox.Show("Error while reading the file: " + ex.Message, "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                }
            }
        }

        private void UpdateValues()
        {
            BeginInvoke((MethodInvoker)delegate
            {
                listBox1.Items[0] = progress.ToString() + "/" + textBox1.Lines.Count().ToString();
                listBox1.Items[1] = "Found: " + yes.ToString();
                listBox1.Items[3] = "MD5: " + MD5.ToString();
                listBox1.Items[4] = "Double MD5: " + DMD5.ToString();
                listBox1.Items[5] = "SHA1: " + SHA1.ToString();
                listBox1.Items[6] = "SHA3: " + SHA3.ToString();
                listBox1.Items[7] = "SHA256: " + SHA256.ToString();
                listBox1.Items[8] = "SHA384: " + SHA384.ToString();
                listBox1.Items[9] = "SHA512: " + SHA512.ToString();
            });
        }

        private async void startbttn_Click(object sender, EventArgs e)
        {
            progress = 0;
            yes = 0;
            MD5 = 0;
            DMD5 = 0;
            SHA1 = 0;
            SHA3 = 0;
            SHA256 = 0;
            SHA384 = 0;
            SHA512 = 0;
            startbttn.Text = "Running";
            startbttn.Enabled = false;
            textBox1.Enabled = false;
            updatetimer.Start();
            await Task.Factory.StartNew(delegate () { UpdateValues(); });
            var options = new ParallelOptions { MaxDegreeOfParallelism = (int)threads.Value };
            await Task.Run(() =>
            {
                Parallel.ForEach(textBox1.Lines.ToList(), options, line =>
                {
                    Dehash(line);
                });
            });
            startbttn.Enabled = true;
            textBox1.Enabled = true;
            startbttn.Text = "Start";
            updatetimer.Stop();
        }

        private void SafeWrite(string line)
        {
            if (textBox2.InvokeRequired)
            {
                textBox2.Invoke(new Action<string>(SafeWrite), line);
            }
            else
            {
                textBox2.AppendText(line + Environment.NewLine);
            }
        }

        private void SortSave(string type, string dehashed, string item)
        {
            SafeWrite(item + ":" + dehashed);
            if (type == "md5")
            {
                MD5++;
                Export("md5.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "double_md5")
            {
                DMD5++;
                Export("double_md5.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "sha1")
            {
                SHA1++;
                Export("sha1.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "sha3")
            {
                SHA3++;
                Export("sha3.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "sha256")
            {
                SHA256++;
                Export("sha256.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "sha384")
            {
                SHA384++;
                Export("sha384.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else if (type == "sha512")
            {
                SHA512++;
                Export("sha512.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
            else
            {
                Export("unknowntype.txt", item + ":" + dehashed + Environment.NewLine);
                Export("all.txt", item + ":" + dehashed + Environment.NewLine);
            }
        }

        private static (string, string) HashToolKit(string hash)
        {
            try
            {
                HttpRequest request = new HttpRequest();
                request.IgnoreProtocolErrors = true;
                request.UserAgent = Http.ChromeUserAgent();
                string req = request.Get("https://hashtoolkit.com/decrypt-hash/?hash=" + hash).ToString();
                Match match = Regex.Match(req, @"(?<=<div class=""panel-heading""><h1 class=""res-header"">Hashes for: <code>).+?(?=</code></h1></div>)");
                if (match.Success)
                {
                    string dehashed = match.Groups[0].Value;
                    if (dehashed != hash)
                    {
                        string type = Regex.Match(req, @"(?<=<span title=""decrypted ).+?(?= hash)").Groups[0].Value;
                        return (type, dehashed);
                    }
                }
                return ("", "");
            }
            catch
            {
                return ("", "");
            }
        }

        private void Dehash(string line)
        {
            try
            {
                string[] com = line.Split(textBox3.Text.ToCharArray());
                string hash = com[hashsplit];
                string item = com[itemsplit];
                bool found = false;
                if (hash.Length >= 16)
                {
                    var output = HashToolKit(hash);
                    if (!string.IsNullOrEmpty(output.Item1))
                    {
                        SortSave(output.Item1.ToLower(), output.Item2, item);
                        found = true;
                    }
                    if (!found & hash.Length == 16)
                    {
                        try
                        {
                            HttpRequest request = new HttpRequest();
                            request.IgnoreProtocolErrors = true;
                            request.UserAgent = Http.ChromeUserAgent();
                            string req = request.Get("https://www.nitrxgen.net/md5db/" + hash).ToString();
                            if (!string.IsNullOrEmpty(req))
                            {
                                SortSave("md5", req, item);
                                found = true;
                            }
                        }
                        catch { }
                        if (!found)
                        {
                            try
                            {
                                HttpRequest request = new HttpRequest();
                                request.IgnoreProtocolErrors = true;
                                request.UserAgent = Http.ChromeUserAgent();
                                string req = request.Get("https://md5.gromweb.com/?md5=" + hash).ToString();
                                Match match = Regex.Match(req, @"(?<=<em class=""long-content string"">).+?(?=</em></p>)");
                                string dehashed = match.Groups[0].Value;
                                if (!string.IsNullOrEmpty(dehashed))
                                {
                                    SortSave("md5", dehashed, item);
                                    found = true;
                                }
                            }
                            catch { }
                        }
                    }
                    if (!found)
                    {
                        try
                        {
                            HttpRequest request = new HttpRequest();
                            request.IgnoreProtocolErrors = true;
                            request.UserAgent = Http.ChromeUserAgent();
                            string req = request.Get("https://sha1.gromweb.com/?hash=" + hash).ToString();
                            Match match = Regex.Match(req, @"(?<=<em class=""long-content string"">).+?(?=</em></p>)");
                            string dehashed = match.Groups[0].Value;
                            if (!string.IsNullOrEmpty(dehashed))
                            {
                                SortSave("sha1", dehashed, item);
                                found = true;
                            }
                        }
                        catch { }
                    }
                    /*if (!found)
                    {
                        try
                        {
                            HttpRequest request = new HttpRequest();
                            request.IgnoreProtocolErrors = true;
                            request.UserAgent = Http.ChromeUserAgent();
                            HttpResponse response = request.Post("https://avine.cf/api/dehash", @"["""+hash+@"""]");
                            if (response.StatusCode == HttpStatusCode.OK)
                            {
                                JArray jsonResponse = JArray.Parse(response.ToString());
                                foreach (var outp in jsonResponse)
                                {
                                    SortSave(outp["algorithm"].ToString(), outp["string"].ToString(), item);
                                    found = true;
                                }
                            }
                        }
                        catch { }
                    }*/
                }
                progress++;
                if (found) { yes++; }
            }
            catch { progress++; }
        }

        public static void Export(string fileName, string DataToSave)
        {
            Lock.EnterWriteLock();
            if (!Directory.Exists("Results"))
            {
                Directory.CreateDirectory("Results");
            }
            if (!Directory.Exists("Results\\" + Date))
            {
                Directory.CreateDirectory("Results\\" + Date);
            }
            try
            {
                using (StreamWriter streamWriter = File.AppendText(string.Concat(new string[]
                {
                    "Results\\", Date, "\\", fileName
                })))
                {
                    streamWriter.WriteLine(DataToSave);
                    streamWriter.Close();
                }
            }
            finally
            {
                Lock.ExitWriteLock();
            }
        }

        private void comboBox1_SelectedIndexChanged(object sender, EventArgs e)
        {
            //0 Item:Hash
            //1 Hash:Item
            int selectedIndex = comboBox1.SelectedIndex;
            if (selectedIndex == 0)
            {
                hashsplit = 1;
                itemsplit = 0;
            }
            if (selectedIndex == 1)
            {
                hashsplit = 0;
                itemsplit = 1;
            }
        }

        private void label3_Click(object sender, EventArgs e)
        {
            Process.Start("https://github.com/machinekillin");
        }

        private void updatetimer_Tick(object sender, EventArgs e)
        {
            UpdateValues();
        }
    }
}
