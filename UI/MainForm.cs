using System;
using System.ComponentModel;
using System.Drawing;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;
using WinEDR_MVP.Engine;
using WinEDR_MVP.Models;

namespace WinEDR_MVP
{
    public partial class MainForm : Form
    {
        private readonly RuleEngine _engine;
        private readonly AlertBroker _broker;
        private readonly BindingList<AlertViewModel> _alertsView = new();
        private CancellationTokenSource? _cts;

        public MainForm(RuleEngine engine, AlertBroker broker)
        {
            _engine = engine;
            _broker = broker;
            InitializeComponent();
            _broker.AlertRaised += HandleAlert;
            dgvAlerts.DataSource = _alertsView;
        }

        private void HandleAlert(Alert alert)
        {
            if (InvokeRequired) { Invoke(HandleAlert, alert); return; }
            _alertsView.Insert(0, new AlertViewModel
            {
                Timestamp   = alert.Timestamp.ToLocalTime().ToString("HH:mm:ss"),
                Severity    = alert.Severity.ToString(),
                Type        = alert.Type.ToString(),
                Title       = alert.Title,
                Description = alert.Description
            });
        }

        private async void btnStart_Click(object sender, EventArgs e)
        {
            if (_cts != null) return;
            _cts = new CancellationTokenSource();
            btnStart.Enabled = false;
            btnStop.Enabled = true;
            statusLabel.Text = "Status: Running...";
            statusLabel.ForeColor = Color.Green;
            scanProgressBar.Visible = true;

            try
            {
                await Task.Run(() => _engine.RunCycle(), _cts.Token);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex)
            {
                MessageBox.Show($"Engine error: {ex.Message}", "Error",
                    MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            finally
            {
                btnStart.Enabled = true;
                btnStop.Enabled = false;
                statusLabel.Text = "Status: Idle";
                statusLabel.ForeColor = Color.Red;
                scanProgressBar.Visible = false;
                _cts = null;
            }
        }

        private void btnStop_Click(object sender, EventArgs e) => _cts?.Cancel();

        protected override void OnFormClosing(FormClosingEventArgs e)
        {
            _broker.AlertRaised -= HandleAlert;
            _cts?.Cancel();
            base.OnFormClosing(e);
        }
    }
}
