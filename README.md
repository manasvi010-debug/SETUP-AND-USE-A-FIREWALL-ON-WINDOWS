# SETUP-AND-USE-A-FIREWALL-ON-WINDOWS
import plotly.graph_objects as go
import json

# Parse the data
data = {"firewall_comparison": [{"aspect": "Interface", "windows": "GUI (wf.msc) or PowerShell", "linux": "CLI commands (sudo ufw)"}, {"aspect": "Default Inbound", "windows": "Blocked", "linux": "Denied (when enabled)"}, {"aspect": "Default Outbound", "windows": "Allowed", "linux": "Allowed"}, {"aspect": "List All Rules", "windows": "Open wf.msc → Inbound/Outbound Rules OR Get-NetFirewallRule -Direction Inbound", "linux": "sudo ufw status OR sudo ufw status numbered"}, {"aspect": "Allow Specific Port", "windows": "GUI: New Rule → Port → Allow OR New-NetFirewallRule -LocalPort 22 -Action Allow", "linux": "sudo ufw allow 22/tcp OR sudo ufw allow ssh"}, {"aspect": "Block Specific Port", "windows": "GUI: New Rule → Port → Block OR New-NetFirewallRule -LocalPort 23 -Action Block", "linux": "sudo ufw deny 23/tcp OR sudo ufw deny telnet"}, {"aspect": "Delete Rule", "windows": "Right-click rule → Delete OR Remove-NetFirewallRule -Name 'rule-name'", "linux": "sudo ufw delete allow 22 OR sudo ufw delete 1 (by number)"}, {"aspect": "Enable Firewall", "windows": "Settings → Firewall & network protection → Turn on", "linux": "sudo ufw enable"}, {"aspect": "Disable Firewall", "windows": "Settings → Firewall & network protection → Turn off", "linux": "sudo ufw disable"}, {"aspect": "Check Status", "windows": "Settings or PowerShell: Get-NetFirewallProfile", "linux": "sudo ufw status verbose"}, {"aspect": "Allow from IP/Subnet", "windows": "GUI: New Rule → Scope → Specific IPs", "linux": "sudo ufw allow from 192.168.1.0/24 to any port 22"}, {"aspect": "Log Location", "windows": "Event Viewer: Windows Logs → Security", "linux": "/var/log/ufw.log"}, {"aspect": "Service Restart", "windows": "Settings or: Restart-Service WinDefend", "linux": "sudo systemctl restart ufw OR sudo service ufw restart"}, {"aspect": "Best Use Case", "windows": "Windows servers and desktops", "linux": "Linux servers and systems"}]}

# Select the specific rows as requested
selected_aspects = [
    "Interface",
    "Default Inbound",
    "Default Outbound",
    "List All Rules",
    "Allow Specific Port",
    "Block Specific Port",
    "Delete Rule",
    "Enable Firewall",
    "Disable Firewall",
    "Log Location",
    "Service Restart",
    "Best Use Case"
]

# Build the table data
aspects = []
windows_cmds = []
linux_cmds = []

for item in data["firewall_comparison"]:
    if item["aspect"] in selected_aspects:
        aspects.append(item["aspect"])
        windows_cmds.append(item["windows"])
        linux_cmds.append(item["linux"])

# Create the table
fig = go.Figure(data=[go.Table(
    header=dict(
        values=['<b>Feature</b>', '<b>Windows Firewall</b>', '<b>Linux UFW</b>'],
        fill_color='#1FB8CD',
        align='left',
        font=dict(color='white', size=14)
    ),
    cells=dict(
        values=[aspects, windows_cmds, linux_cmds],
        fill_color=[['#f9f9f9', 'white'] * len(aspects)],
        align='left',
        font=dict(size=12),
        height=30
    )
)])

fig.update_layout(
    title='Windows Firewall vs Linux UFW'
)
import plotly.graph_objects as go

# Create figure
fig = go.Figure()

# Define node positions (x, y)
# Column-based layout for clarity
nodes = {
    'start': (0.5, 10),
    'extract': (0.5, 9),
    'state_check': (0.5, 8),
    'allow_state': (0.2, 7),
    'rule_eval': (0.8, 7),
    'rule_match': (0.8, 6),
    'action': (0.65, 5),
    'more_rules': (0.95, 5),
    'default': (0.95, 4),
    'end': (0.5, 3)
}

# Define node shapes and labels
node_info = {
    'start': {'label': 'START<br>Packet arrives', 'shape': 'circle'},
    'extract': {'label': 'Extract header:<br>IP, port, protocol', 'shape': 'rect'},
    'state_check': {'label': 'Established<br>connection?', 'shape': 'diamond'},
    'allow_state': {'label': 'Allow<br>(Stateful)', 'shape': 'rect'},
    'rule_eval': {'label': 'Check rules<br>sequentially', 'shape': 'rect'},
    'rule_match': {'label': 'Rule<br>matches?', 'shape': 'diamond'},
    'action': {'label': 'Execute action<br>Allow/Block/Reject', 'shape': 'rect'},
    'more_rules': {'label': 'More<br>rules?', 'shape': 'diamond'},
    'default': {'label': 'Apply default<br>policy', 'shape': 'rect'},
    'end': {'label': 'END<br>Fwd or dropped', 'shape': 'circle'}
}

# Define edges with labels
edges = [
    ('start', 'extract', ''),
    ('extract', 'state_check', ''),
    ('state_check', 'allow_state', 'Yes'),
    ('state_check', 'rule_eval', 'No'),
    ('allow_state', 'end', ''),
    ('rule_eval', 'rule_match', ''),
    ('rule_match', 'action', 'Yes'),
    ('rule_match', 'more_rules', 'No'),
    ('action', 'end', ''),
    ('more_rules', 'rule_eval', 'Yes'),
    ('more_rules', 'default', 'No'),
    ('default', 'end', '')
]

# Draw edges (arrows)
for start_node, end_node, label in edges:
    x0, y0 = nodes[start_node]
    x1, y1 = nodes[end_node]
    
    # Add arrow line
    fig.add_trace(go.Scatter(
        x=[x0, x1],
        y=[y0, y1],
        mode='lines',
        line=dict(color='#21808d', width=2),
        hoverinfo='skip',
        showlegend=False
    ))
    
    # Add arrowhead
    fig.add_annotation(
        x=x1, y=y1,
        ax=x0, ay=y0,
        xref='x', yref='y',
        axref='x', ayref='y',
        showarrow=True,
        arrowhead=2,
        arrowsize=1,
        arrowwidth=2,
        arrowcolor='#21808d',
        text=''
    )
    
    # Add edge label if exists
    if label:
        mid_x, mid_y = (x0 + x1) / 2, (y0 + y1) / 2
        fig.add_annotation(
            x=mid_x, y=mid_y,
            text=label,
            showarrow=False,
            font=dict(size=10, color='#13343b'),
            bgcolor='#f3f3ee',
            borderpad=2
        )

# Draw nodes
for node_name, info in node_info.items():
    x, y = nodes[node_name]
    label = info['label']
    shape = info['shape']
    
    if shape == 'circle':
        # Start/End nodes
        fig.add_trace(go.Scatter(
            x=[x], y=[y],
            mode='markers+text',
            marker=dict(size=60, color='#B3E5EC', line=dict(color='#21808d', width=2)),
            text=label,
            textposition='middle center',
            textfont=dict(size=9, color='#13343b'),
            hoverinfo='skip',
            showlegend=False
        ))
    elif shape == 'diamond':
        # Decision nodes
        fig.add_trace(go.Scatter(
            x=[x, x+0.06, x, x-0.06, x],
            y=[y+0.25, y, y-0.25, y, y+0.25],
            mode='lines',
            fill='toself',
            fillcolor='#FFEB8A',
            line=dict(color='#21808d', width=2),
            hoverinfo='skip',
            showlegend=False
        ))
        fig.add_annotation(
            x=x, y=y,
            text=label,
            showarrow=False,
            font=dict(size=9, color='#13343b')
        )
    else:
        # Rectangle nodes
        fig.add_shape(
            type='rect',
            x0=x-0.08, y0=y-0.2,
            x1=x+0.08, y1=y+0.2,
            fillcolor='#B3E5EC',
            line=dict(color='#21808d', width=2)
        )
        fig.add_annotation(
            x=x, y=y,
            text=label,
            showarrow=False,
            font=dict(size=9, color='#13343b')
        )

# Update layout
fig.update_layout(
    title='Firewall Network Traffic Filter',
    xaxis=dict(visible=False, range=[0, 1.2]),
    yaxis=dict(visible=False, range=[2, 11]),
    plot_bgcolor='#f3f3ee',
    paper_bgcolor='#f3f3ee'
)

# Save the chart
fig.write_image('firewall_flow.png')
fig.write_image('firewall_flow.svg', format='svg')
print("Chart saved successfully")
# Create comprehensive command reference guides
commands_guide = """# FIREWALL COMMANDS QUICK REFERENCE

## WINDOWS FIREWALL COMMANDS (PowerShell)

### View Rules
Get-NetFirewallRule -Direction Inbound | Format-Table Name, Direction, Action, Enabled
Get-NetFirewallRule -DisplayName "Block Telnet" | Format-List *
Get-NetFirewallRule -Enabled True | Measure-Object

### Create Rules
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -LocalPort 22 -Protocol TCP -Action Allow
New-NetFirewallRule -DisplayName "Block Telnet" -Direction Inbound -LocalPort 23 -Protocol TCP -Action Block
New-NetFirewallRule -DisplayName "Block from IP" -Direction Inbound -RemoteAddress 192.168.1.100 -Action Block

### Delete Rules
Remove-NetFirewallRule -DisplayName "Allow SSH"
Get-NetFirewallRule -DisplayName "Old Rule" | Remove-NetFirewallRule

### Modify Rules
Set-NetFirewallRule -DisplayName "Allow SSH" -Enabled True
Set-NetFirewallRule -DisplayName "Allow SSH" -Enabled False

### Disable/Enable Firewall
Set-NetFirewallProfile -All -Enabled False  # Disable all profiles
Set-NetFirewallProfile -All -Enabled True   # Enable all profiles

### Export/Import Rules
Export-NetFirewallRule -PolicyStore PersistentStore -Folder C:\\Firewall
Import-NetFirewallRule -InputObject (Get-NetFirewallRule) -PolicyStore PersistentStore

---

## LINUX UFW COMMANDS

### Basic Management
sudo ufw status                    # Check firewall status
sudo ufw status verbose            # Detailed status with policies
sudo ufw status numbered           # List rules with numbers
sudo ufw enable                    # Enable firewall
sudo ufw disable                   # Disable firewall
sudo ufw reset                     # Remove all rules and disable

### Set Default Policies
sudo ufw default deny incoming     # Block all incoming (recommended)
sudo ufw default allow incoming    # Allow all incoming (not recommended)
sudo ufw default allow outgoing    # Allow all outgoing
sudo ufw default deny outgoing     # Block all outgoing

### Allow Specific Ports/Services
sudo ufw allow 22/tcp              # Allow SSH (port 22, TCP)
sudo ufw allow 22                  # Allow port 22 (both TCP/UDP)
sudo ufw allow ssh                 # Allow SSH by service name
sudo ufw allow http                # Allow HTTP (port 80)
sudo ufw allow https               # Allow HTTPS (port 443)
sudo ufw allow 20-25               # Allow port range
sudo ufw allow 22,80,443/tcp       # Allow multiple ports

### Block Specific Ports/Services
sudo ufw deny 23/tcp               # Block Telnet (port 23, TCP)
sudo ufw deny 23                   # Block port 23 (both TCP/UDP)
sudo ufw deny telnet               # Block Telnet by service name
sudo ufw deny 53                   # Block DNS port 53

### Rules with IP Addresses
sudo ufw allow from 192.168.1.1                # Allow all from specific IP
sudo ufw allow from 192.168.1.0/24             # Allow all from subnet
sudo ufw allow from 192.168.1.1 to any port 22 # Allow IP to specific port
sudo ufw deny from 203.0.113.0/24              # Block entire subnet

### Delete Rules
sudo ufw delete allow 22           # Delete rule by specification
sudo ufw delete deny 23/tcp        # Delete deny rule
sudo ufw delete 1                  # Delete rule #1 (by number)
sudo ufw delete allow from 192.168.1.1

### Logging
sudo ufw logging on                # Enable firewall logging
sudo ufw logging off               # Disable logging
sudo ufw logging high              # High level logging
sudo tail -f /var/log/ufw.log      # View firewall logs
journalctl -u ufw | tail -n 20     # View recent firewall events

---

## TESTING CONNECTIVITY

### Netcat (nc/ncat)
nc -zv 192.168.1.100 22            # Test if port 22 is open
nc -zv 192.168.1.100 1-100         # Scan ports 1-100
nc -zv -w 3 host port             # Test with 3 second timeout

### Telnet
telnet 192.168.1.100 22            # Test port 22
telnet localhost 23                # Test local port 23

### PowerShell (Windows)
Test-NetConnection -ComputerName localhost -Port 23
Test-NetConnection -ComputerName 192.168.1.100 -Port 22 -InformationLevel Detailed

### Nmap
nmap -p 22 192.168.1.100           # Scan specific port
nmap -p 1-1000 192.168.1.100       # Scan port range
nmap -p- 192.168.1.100             # Scan all ports

---

## VIEWING LISTENING PORTS

### Linux
netstat -tulpn | grep LISTEN       # Show listening ports (netstat)
ss -tulpn | grep LISTEN            # Show listening ports (ss - newer)
lsof -i :22                        # Show services on port 22
sudo netstat -tulpn | grep 23      # Check if port 23 is listening

### Windows PowerShell
Get-NetTCPConnection -State Listen # Show listening connections
netstat -ano | findstr :22         # Show port 22 connections
Get-Process -Id (Get-NetTCPConnection -LocalPort 22).OwningProcess

---

## VERIFICATION CHECKLIST

After creating firewall rules:

❑ Rule appears in rule list
❑ Rule status shows as ENABLED
❑ Test connection matches rule intent
❑ SSH access maintained (critical!)
❑ Service is actually running on port
❑ No conflicting rules exist
❑ Firewall is active/enabled
"""

with open('firewall_commands_reference.txt', 'w') as f:
    f.write(commands_guide)

print("✓ Firewall Commands Reference created!")
print("File saved: firewall_commands_reference.txt")
print(f"Content size: {len(commands_guide)} characters")

# Save as PNG and SVG
fig.write_image('firewall_comparison.png')
fig.write_image('firewall_comparison.svg', format='svg')
