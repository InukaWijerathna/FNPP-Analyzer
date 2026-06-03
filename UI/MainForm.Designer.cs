
namespace WinEDR_MVP
{
    partial class MainForm
    {
        private System.ComponentModel.IContainer components = null;

        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        private void InitializeComponent()
        {
            this.components = new System.ComponentModel.Container();
            this.dgvAlerts = new System.Windows.Forms.DataGridView();
            this.btnStart = new System.Windows.Forms.Button();
            this.btnStop = new System.Windows.Forms.Button();
            this.statusStrip1 = new System.Windows.Forms.StatusStrip();
            this.statusLabel = new System.Windows.Forms.ToolStripStatusLabel();
            this.scanProgressBar = new System.Windows.Forms.ToolStripProgressBar();
            this.panelTop = new System.Windows.Forms.Panel();
            this.labelHeader = new System.Windows.Forms.Label();

            ((System.ComponentModel.ISupportInitialize)(this.dgvAlerts)).BeginInit();
            this.statusStrip1.SuspendLayout();
            this.panelTop.SuspendLayout();
            this.SuspendLayout();

            // panelTop
            this.panelTop.BackColor = System.Drawing.Color.FromArgb(45, 45, 45);
            this.panelTop.Controls.Add(this.labelHeader);
            this.panelTop.Controls.Add(this.btnStart);
            this.panelTop.Controls.Add(this.btnStop);
            this.panelTop.Dock = System.Windows.Forms.DockStyle.Top;
            this.panelTop.Height = 70;
            this.panelTop.Padding = new System.Windows.Forms.Padding(10);

            // labelHeader
            this.labelHeader.Text = "WinEDR MVP";
            this.labelHeader.ForeColor = System.Drawing.Color.White;
            this.labelHeader.Font = new System.Drawing.Font("Segoe UI Semibold", 16F);
            this.labelHeader.Location = new System.Drawing.Point(20, 18);
            this.labelHeader.AutoSize = true;

            // btnStart
            this.btnStart.Text = "Start Scan";
            this.btnStart.Location = new System.Drawing.Point(200, 20);
            this.btnStart.Size = new System.Drawing.Size(120, 32);
            this.btnStart.Click += new System.EventHandler(this.btnStart_Click);
            this.btnStart.BackColor = System.Drawing.Color.FromArgb(0, 95, 184);
            this.btnStart.ForeColor = System.Drawing.Color.White;
            this.btnStart.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnStart.FlatAppearance.BorderSize = 0;
            this.btnStart.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnStart.Font = new System.Drawing.Font("Segoe UI", 10F);

            // btnStop
            this.btnStop.Text = "Cancel";
            this.btnStop.Location = new System.Drawing.Point(330, 20);
            this.btnStop.Size = new System.Drawing.Size(120, 32);
            this.btnStop.Click += new System.EventHandler(this.btnStop_Click);
            this.btnStop.Enabled = false;
            this.btnStop.BackColor = System.Drawing.Color.FromArgb(196, 43, 28);
            this.btnStop.ForeColor = System.Drawing.Color.White;
            this.btnStop.FlatStyle = System.Windows.Forms.FlatStyle.Flat;
            this.btnStop.FlatAppearance.BorderSize = 0;
            this.btnStop.Cursor = System.Windows.Forms.Cursors.Hand;
            this.btnStop.Font = new System.Drawing.Font("Segoe UI", 10F);

            // dgvAlerts
            this.dgvAlerts.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dgvAlerts.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dgvAlerts.AutoSizeColumnsMode = System.Windows.Forms.DataGridViewAutoSizeColumnsMode.Fill;
            this.dgvAlerts.ReadOnly = true;
            this.dgvAlerts.RowHeadersVisible = false;
            this.dgvAlerts.AllowUserToAddRows = false;
            this.dgvAlerts.BackgroundColor = System.Drawing.Color.FromArgb(32, 32, 32);
            this.dgvAlerts.BorderStyle = System.Windows.Forms.BorderStyle.None;
            this.dgvAlerts.CellBorderStyle = System.Windows.Forms.DataGridViewCellBorderStyle.SingleHorizontal;
            this.dgvAlerts.GridColor = System.Drawing.Color.FromArgb(60, 60, 60);
            this.dgvAlerts.EnableHeadersVisualStyles = false;

            var cellStyle = new System.Windows.Forms.DataGridViewCellStyle
            {
                BackColor = System.Drawing.Color.FromArgb(32, 32, 32),
                ForeColor = System.Drawing.Color.White,
                SelectionBackColor = System.Drawing.Color.FromArgb(0, 95, 184),
                SelectionForeColor = System.Drawing.Color.White,
                Padding = new System.Windows.Forms.Padding(5)
            };
            this.dgvAlerts.DefaultCellStyle = cellStyle;
            this.dgvAlerts.RowTemplate.Height = 35;

            var headerStyle = new System.Windows.Forms.DataGridViewCellStyle
            {
                BackColor = System.Drawing.Color.FromArgb(45, 45, 45),
                ForeColor = System.Drawing.Color.White,
                Font = new System.Drawing.Font("Segoe UI Semibold", 10F),
                SelectionBackColor = System.Drawing.Color.FromArgb(45, 45, 45),
                Padding = new System.Windows.Forms.Padding(5)
            };
            this.dgvAlerts.ColumnHeadersDefaultCellStyle = headerStyle;
            this.dgvAlerts.ColumnHeadersBorderStyle = System.Windows.Forms.DataGridViewHeaderBorderStyle.None;

            // statusStrip1
            this.statusStrip1.Items.AddRange(new System.Windows.Forms.ToolStripItem[]
                { this.statusLabel, this.scanProgressBar });
            this.statusStrip1.BackColor = System.Drawing.Color.FromArgb(45, 45, 45);
            this.statusStrip1.ForeColor = System.Drawing.Color.White;

            // statusLabel
            this.statusLabel.Name = "statusLabel";
            this.statusLabel.Text = "Status: Idle";

            // scanProgressBar
            this.scanProgressBar.Name = "scanProgressBar";
            this.scanProgressBar.Size = new System.Drawing.Size(100, 16);
            this.scanProgressBar.Style = System.Windows.Forms.ProgressBarStyle.Marquee;
            this.scanProgressBar.Visible = false;

            // MainForm
            this.AutoScaleDimensions = new System.Drawing.SizeF(7F, 17F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.ClientSize = new System.Drawing.Size(900, 500);
            this.Controls.Add(this.dgvAlerts);
            this.Controls.Add(this.statusStrip1);
            this.Controls.Add(this.panelTop);
            this.Name = "MainForm";
            this.Text = "WinEDR MVP";
            this.BackColor = System.Drawing.Color.FromArgb(32, 32, 32);
            this.Font = new System.Drawing.Font("Segoe UI", 10F);

            ((System.ComponentModel.ISupportInitialize)(this.dgvAlerts)).EndInit();
            this.statusStrip1.ResumeLayout(false);
            this.statusStrip1.PerformLayout();
            this.panelTop.ResumeLayout(false);
            this.panelTop.PerformLayout();
            this.ResumeLayout(false);
            this.PerformLayout();
        }

        private System.Windows.Forms.DataGridView dgvAlerts;
        private System.Windows.Forms.Button btnStart;
        private System.Windows.Forms.Button btnStop;
        private System.Windows.Forms.StatusStrip statusStrip1;
        private System.Windows.Forms.ToolStripStatusLabel statusLabel;
        private System.Windows.Forms.ToolStripProgressBar scanProgressBar;
        private System.Windows.Forms.Panel panelTop;
        private System.Windows.Forms.Label labelHeader;
    }
}
