using System;
using System.Diagnostics;
using System.Drawing;
using System.Windows.Forms;

namespace DissertationGUI
{
    // program starts here
    internal static class Program
    {
        [STAThread]
        static void Main()
        {
            ApplicationConfiguration.Initialize();
            Application.Run(new SecurityDashboardForm());
        }
    }

    // main window
    public class SecurityDashboardForm : Form
    {
        // panels for layout
        private Panel sidebarPanel;
        private Panel headerPanel;
        private Panel mainContentPanel;
        private Panel resultsCardPanel;

        // UI elements
        private Label dashboardTitleLabel;
        private RichTextBox resultsOutputBox;
        private SimpleButton startScanButton;

        // keep track of what scan type user selected
        private string selectedScanType = "Full Scan";

        public SecurityDashboardForm()
        {
            // window settings
            Text = "System Scanning";
            Width = 1280;
            Height = 1080;
            MinimumSize = new Size(900, 600);
            BackColor = ColorTranslator.FromHtml("#FFFEF7");
            Font = new Font("Segoe UI", 12);

            // sidebar on left
            sidebarPanel = new Panel();
            sidebarPanel.BackColor = ColorTranslator.FromHtml("#2B2B2B");
            sidebarPanel.Width = 250;
            sidebarPanel.Dock = DockStyle.Left;
            sidebarPanel.Padding = new Padding(0, 50, 0, 0);
            Controls.Add(sidebarPanel);

            // add sidebar buttons
            AddSidebarItem("Full Scan");
            AddSidebarItem("Antivirus");
            AddSidebarItem("Firewall");
            AddSidebarItem("Password");
            AddSidebarItem("Windows Update");
            AddSidebarItem("User Account Control");

            // header at top
            headerPanel = new Panel();
            headerPanel.BackColor = ColorTranslator.FromHtml("#1E3A8A");
            headerPanel.Height = 80;
            headerPanel.Dock = DockStyle.Top;
            headerPanel.Padding = new Padding(20, 20, 20, 20);
            Controls.Add(headerPanel);

            // title in header
            dashboardTitleLabel = new Label();
            dashboardTitleLabel.ForeColor = Color.White;
            dashboardTitleLabel.Text = selectedScanType;
            dashboardTitleLabel.Font = new Font("Segoe UI", 20, FontStyle.Bold);
            dashboardTitleLabel.AutoSize = true;
            headerPanel.Controls.Add(dashboardTitleLabel);

            // start scan button
            startScanButton = new SimpleButton();
            startScanButton.Text = "Start Scan";
            startScanButton.Width = 200;
            startScanButton.Height = 40;
            startScanButton.BackColor = ColorTranslator.FromHtml("#228B22");
            startScanButton.ForeColor = ColorTranslator.FromHtml("#FFFFFF");
            startScanButton.Font = new Font("Segoe UI", 15, FontStyle.Bold);
            startScanButton.FlatStyle = FlatStyle.Flat;
            startScanButton.Cursor = Cursors.Hand;
            startScanButton.FlatAppearance.BorderSize = 0;
            startScanButton.Anchor = AnchorStyles.Top | AnchorStyles.Right;
            startScanButton.Location = new Point(headerPanel.Width - startScanButton.Width - 20, 20);
            startScanButton.Click += StartScanButton_Click;
            headerPanel.Controls.Add(startScanButton);

            // keep button on right when window resizes
            headerPanel.Resize += HeaderPanel_Resize;

            // main area in middle
            mainContentPanel = new Panel();
            mainContentPanel.Dock = DockStyle.Fill;
            mainContentPanel.Padding = new Padding(20);

            // white card for results
            resultsCardPanel = new Panel();
            resultsCardPanel.Dock = DockStyle.Fill;
            resultsCardPanel.BackColor = ColorTranslator.FromHtml("#FFFEF7");
            resultsCardPanel.Padding = new Padding(20);
            mainContentPanel.Controls.Add(resultsCardPanel);

            // text box for output
            resultsOutputBox = new RichTextBox();
            resultsOutputBox.ReadOnly = true;
            resultsOutputBox.BackColor = ColorTranslator.FromHtml("#FFFEF7");
            resultsOutputBox.ForeColor = ColorTranslator.FromHtml("#1A1A1A");
            resultsOutputBox.Font = new Font("Consolas", 12);
            resultsOutputBox.BorderStyle = BorderStyle.None;
            resultsOutputBox.Dock = DockStyle.Fill;
            resultsOutputBox.Text = "Please press 'Start Scan' to start scanning for " + selectedScanType;
            resultsCardPanel.Controls.Add(resultsOutputBox);

            // add panels to form
            Controls.Add(mainContentPanel);
            Controls.Add(headerPanel);
            Controls.Add(sidebarPanel);
        }

        // add item to sidebar
        private void AddSidebarItem(string text)
        {
            Label label = new Label();
            label.Text = text;
            label.ForeColor = Color.LightGray;
            label.Font = new Font("Segoe UI", 12);
            label.Height = 50;
            label.Dock = DockStyle.Top;
            label.Padding = new Padding(20, 15, 0, 0);
            label.BackColor = ColorTranslator.FromHtml("#2B2B2B");
            label.Cursor = Cursors.Hand;

            // when mouse goes over item
            label.MouseEnter += SidebarItem_MouseEnter;

            // when mouse leaves item
            label.MouseLeave += SidebarItem_MouseLeave;

            // when user clicks item
            label.Click += SidebarItem_Click;

            sidebarPanel.Controls.Add(label);
            sidebarPanel.Controls.SetChildIndex(label, 0);
        }

        // change color when mouse enters
        private void SidebarItem_MouseEnter(object sender, EventArgs e)
        {
            Label label = (Label)sender;
            label.BackColor = ColorTranslator.FromHtml("#404040");
        }

        // change color back when mouse leaves
        private void SidebarItem_MouseLeave(object sender, EventArgs e)
        {
            Label label = (Label)sender;
            label.BackColor = ColorTranslator.FromHtml("#2B2B2B");
        }

        // user clicked sidebar item
        private void SidebarItem_Click(object sender, EventArgs e)
        {
            Label label = (Label)sender;
            selectedScanType = label.Text;
            dashboardTitleLabel.Text = selectedScanType;
            resultsOutputBox.Text = "Selected: " + selectedScanType + "\nClick 'Start Scan' to begin";
        }

        // keep button positioned correctly
        private void HeaderPanel_Resize(object sender, EventArgs e)
        {
            startScanButton.Left = headerPanel.Width - startScanButton.Width - 20;
        }

        // run scan when button clicked
        private void StartScanButton_Click(object sender, EventArgs e)
        {
            if (selectedScanType == "Full Scan")
            {
                resultsOutputBox.Text = "Running Full Scan. It may take a while\n\n";
            }
            else
            {
                resultsOutputBox.Text = "Running " + selectedScanType + " scan. It may take a while\n\n";
            }
            Application.DoEvents();

            try
            {
                // setup python process
                ProcessStartInfo startConfig = new ProcessStartInfo();
                startConfig.FileName = "python";
                
                // pass scan type to python script
                startConfig.Arguments = "dissertation.py \"" + selectedScanType + "\"";
                
                startConfig.RedirectStandardOutput = true;
                startConfig.RedirectStandardError = true;
                startConfig.UseShellExecute = false;
                startConfig.CreateNoWindow = true;

                // start python
                Process process = Process.Start(startConfig);

                if (process == null)
                {
                    resultsOutputBox.Text = "Could not run the Python code";
                    return;
                }

                // get output from python
                string output = process.StandardOutput.ReadToEnd();
                string errors = process.StandardError.ReadToEnd();
                process.WaitForExit();

                // show results
                if (output == "")
                {
                    resultsOutputBox.Text = "No output\n\n" + errors;
                }
                else
                {
                    resultsOutputBox.Text = "";
                    
                    // adding colored output line by line
                    string[] lines = output.Split('\n');
                    foreach (string line in lines)
                    {
                        if (line.Contains("PASS"))
                        {
                            // adding green tick and making the line green
                            resultsOutputBox.SelectionColor = Color.Green;
                            resultsOutputBox.AppendText("✓ " + line + "\n");
                        }
                        else if (line.Contains("FAIL"))
                        {
                            // adding red cross and making the line red
                            resultsOutputBox.SelectionColor = Color.Red;
                            resultsOutputBox.AppendText("✗ " + line + "\n");
                        }
                        else
                        {
                            // normal black text
                            resultsOutputBox.SelectionColor = Color.Black;
                            resultsOutputBox.AppendText(line + "\n");
                        }
                    }
                    
                    // add errors if any
                    if (errors != "")
                    {
                        resultsOutputBox.SelectionColor = Color.Red;
                        resultsOutputBox.AppendText("\n" + errors);
                    }
                    
                    // reset color back to black
                    resultsOutputBox.SelectionColor = Color.Black;
                }
            }
            catch (Exception ex)
            {
                resultsOutputBox.Text = "Error: " + ex.Message;
            }
        }
    }

    // simple flat button
    public class SimpleButton : Button
    {
        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            // fill button with color
            SolidBrush brush = new SolidBrush(this.BackColor);
            e.Graphics.FillRectangle(brush, this.ClientRectangle);
            brush.Dispose();

            // draw text in center
            TextRenderer.DrawText(
                e.Graphics,
                this.Text,
                this.Font,
                this.ClientRectangle,
                this.ForeColor,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter
            );
        }
    }
}