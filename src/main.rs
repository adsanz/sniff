use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use dns_lookup::lookup_addr;
use pcap::{Capture, Device};
use pnet::packet::{
    ethernet::EthernetPacket, ip::IpNextHeaderProtocols, ipv4::Ipv4Packet, tcp::TcpPacket,
    udp::UdpPacket, Packet,
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    layout::{Constraint, Direction, Layout, Rect},
    style::{Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};
use std::{
    collections::HashMap,
    net::IpAddr,
    sync::mpsc::{channel, Receiver},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

#[derive(Clone, Debug)]
struct Connection {
    source: IpAddr,
    destination: IpAddr,
    port: u16,
    protocol: Protocol,
    bytes: u64,
    last_seen: u64,
}

#[derive(Clone, Debug, PartialEq)]
enum Protocol {
    Tcp,
    Udp,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum InputMode {
    Normal,
    Source,
    Destination,
}

#[derive(Debug)]
enum Message {
    NewConnection(Connection),
    UpdateStats,
}

#[derive(Debug, Clone, Copy)]
enum ActivePanel {
    Tcp,
    Udp,
    Ports,
    ResolvedHosts,
    Tree,
}

struct AppState {
    connections: Vec<Connection>,
    port_stats: HashMap<u16, usize>,
    resolved_hosts: HashMap<IpAddr, String>,
    connection_tree: HashMap<IpAddr, Vec<Connection>>,
}

struct App {
    state: AppState,
    active_panel: ActivePanel,
    panel_states: Vec<ListState>,
    scroll_positions: Vec<usize>,
    rx: Receiver<Message>,
    source_filter: Option<String>,
    dest_filter: Option<String>,
    input_mode: InputMode,
    input_value: String,
}

impl App {
    fn new(rx: Receiver<Message>) -> Self {
        Self {
            state: AppState {
                connections: Vec::new(),
                port_stats: HashMap::new(),
                resolved_hosts: HashMap::new(),
                connection_tree: HashMap::new(),
            },
            active_panel: ActivePanel::Tcp,
            panel_states: vec![ListState::default(); 5],
            scroll_positions: vec![0; 5],
            rx,
            source_filter: None,
            dest_filter: None,
            input_mode: InputMode::Normal,
            input_value: String::new(),
        }
    }

    fn get_layout_constraints(&self) -> Vec<Constraint> {
        let mut constraints = vec![
            Constraint::Percentage(50), // Main content
            Constraint::Percentage(50), // More content
        ];

        if self.input_mode != InputMode::Normal {
            constraints.push(Constraint::Length(3)); // Reserve space for input
        }

        constraints
    }

    fn bottom_rect(height: u16, r: Rect) -> Rect {
        let popup_layout = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(1),
                Constraint::Length(height),
                Constraint::Length(1), // bottom padding
            ])
            .split(r);

        // Add horizontal padding
        Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Length(2), // left padding
                Constraint::Min(1),
                Constraint::Length(2), // right padding
            ])
            .split(popup_layout[1])[1]
    }

    fn render_input_popup<B: Backend>(&self, f: &mut Frame<B>) {
        if self.input_mode == InputMode::Normal {
            return;
        }

        let prompt = match self.input_mode {
            InputMode::Source => "Enter source filter (regex):",
            InputMode::Destination => "Enter destination filter (regex):",
            _ => unreachable!(),
        };

        // Create centered popup
        let area = App::bottom_rect(3, f.size());

        let input_block = Block::default()
            .title(prompt)
            .borders(Borders::ALL)
            .style(Style::default().add_modifier(Modifier::BOLD));

        let input = Paragraph::new(self.input_value.as_str())
            .style(Style::default().add_modifier(Modifier::REVERSED))
            .block(input_block);

        f.render_widget(Clear, area); // Clear background
        f.render_widget(input, area);
    }

    fn matches_filters(&self, conn: &Connection) -> bool {
        let source_matches = self.source_filter.as_ref().map_or(true, |filter| {
            regex::Regex::new(filter).map_or(false, |re| re.is_match(&conn.source.to_string()))
        });

        let dest_matches = self.dest_filter.as_ref().map_or(true, |filter| {
            regex::Regex::new(filter).map_or(false, |re| re.is_match(&conn.destination.to_string()))
        });

        source_matches && dest_matches
    }

    fn format_bytes(&self, bytes: u64) -> String {
        if bytes < 1024 {
            format!("{} B", bytes)
        } else if bytes < 1024 * 1024 {
            format!("{:.2} KB", bytes as f64 / 1024.0)
        } else {
            format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
        }
    }

    fn is_active(&self, last_seen: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now.saturating_sub(last_seen) < 10
    }

    fn scroll(&mut self, direction: Direction) {
        let panel_index = match self.active_panel {
            ActivePanel::Tcp => 0,
            ActivePanel::Udp => 1,
            ActivePanel::Ports => 2,
            ActivePanel::ResolvedHosts => 3,
            ActivePanel::Tree => 4,
        };

        let list_length = match self.active_panel {
            ActivePanel::Tcp => self
                .state
                .connections
                .iter()
                .filter(|c| c.protocol == Protocol::Tcp)
                .count(),
            ActivePanel::Udp => self
                .state
                .connections
                .iter()
                .filter(|c| c.protocol == Protocol::Udp)
                .count(),
            ActivePanel::Ports => self.state.port_stats.len(),
            ActivePanel::ResolvedHosts => self.state.resolved_hosts.len(),
            ActivePanel::Tree => self
                .state
                .connection_tree
                .iter()
                .map(|(_, conns)| 1 + conns.len())
                .sum(),
        };

        match direction {
            Direction::Horizontal if self.scroll_positions[panel_index] > 0 => {
                self.scroll_positions[panel_index] -= 1;
            }
            Direction::Vertical
                if self.scroll_positions[panel_index] < list_length.saturating_sub(1) =>
            {
                self.scroll_positions[panel_index] += 1;
            }
            _ => {}
        }

        let list_state = &mut self.panel_states[panel_index];
        list_state.select(Some(self.scroll_positions[panel_index]));
    }

    fn update(&mut self) {
        while let Ok(msg) = self.rx.try_recv() {
            match msg {
                Message::NewConnection(conn) => self.handle_connection(conn),
                Message::UpdateStats => self.update_stats(),
            }
        }
    }

    fn handle_connection(&mut self, conn: Connection) {
        *self.state.port_stats.entry(conn.port).or_default() += 1;
        if !self.state.resolved_hosts.contains_key(&conn.destination) {
            if let Ok(name) = lookup_addr(&conn.destination) {
                self.state.resolved_hosts.insert(conn.destination, name);
            }
        }
        self.state
            .connection_tree
            .entry(conn.source)
            .or_default()
            .push(conn.clone());

        self.state.connections.push(conn);
    }

    fn update_stats(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.state
            .connections
            .retain(|conn| now - conn.last_seen < 60);
        for connections in self.state.connection_tree.values_mut() {
            connections.retain(|conn| now - conn.last_seen < 60);
        }
    }

    fn render<B: Backend>(&mut self, f: &mut Frame<B>) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints(self.get_layout_constraints())
            .split(f.size());

        let main_area = if self.input_mode != InputMode::Normal {
            &chunks[0]
        } else {
            &f.size()
        };

        // Split main area horizontally
        let horizontal_chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)].as_ref())
            .split(*main_area);

        let left_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(33),
                Constraint::Percentage(33),
                Constraint::Percentage(34),
            ])
            .split(horizontal_chunks[0]);

        let right_chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(30), Constraint::Percentage(70)].as_ref())
            .split(horizontal_chunks[1]);

        // Render panels
        self.render_tcp_panel(f, left_chunks[0]);
        self.render_udp_panel(f, left_chunks[1]);
        self.render_ports_panel(f, left_chunks[2]);
        self.render_resolved_panel(f, right_chunks[0]);
        self.render_tree_panel(f, right_chunks[1]);
        if self.input_mode != InputMode::Normal {
            self.render_input_popup(f);
        }
    }

    fn render_list<B: Backend>(
        &self,
        f: &mut Frame<B>,
        items: Vec<ListItem>,
        title: &str,
        area: ratatui::layout::Rect,
        panel_index: usize,
    ) {
        let is_active = match (self.active_panel, panel_index) {
            (ActivePanel::Tcp, 0) => true,
            (ActivePanel::Udp, 1) => true,
            (ActivePanel::Ports, 2) => true,
            (ActivePanel::ResolvedHosts, 3) => true,
            (ActivePanel::Tree, 4) => true,
            _ => false,
        };

        let block = Block::default().title(title).borders(Borders::ALL).style(
            Style::default().add_modifier(if is_active {
                Modifier::BOLD
            } else {
                Modifier::empty()
            }),
        );

        let list = List::new(items)
            .block(block)
            .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

        f.render_stateful_widget(list, area, &mut self.panel_states[panel_index].clone());
    }

    fn render_tcp_panel<B: Backend>(&self, f: &mut Frame<B>, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .state
            .connections
            .iter()
            .filter(|c| c.protocol == Protocol::Tcp && self.matches_filters(c))
            .map(|conn| {
                ListItem::new(format!(
                    "{} -> {}:{} ({} bytes)",
                    conn.source, conn.destination, conn.port, conn.bytes
                ))
            })
            .collect();

        self.render_list(f, items, "TCP Connections", area, 0);
    }

    fn render_udp_panel<B: Backend>(&self, f: &mut Frame<B>, area: ratatui::layout::Rect) {
        let items: Vec<ListItem> = self
            .state
            .connections
            .iter()
            .filter(|c| c.protocol == Protocol::Udp && self.matches_filters(c))
            .map(|conn| {
                ListItem::new(format!(
                    "{} -> {}:{} ({} bytes)",
                    conn.source, conn.destination, conn.port, conn.bytes
                ))
            })
            .collect();

        self.render_list(f, items, "UDP Connections", area, 1);
    }

    fn render_ports_panel<B: Backend>(&self, f: &mut Frame<B>, area: ratatui::layout::Rect) {
        let mut items: Vec<(u16, usize)> = self
            .state
            .port_stats
            .iter()
            .map(|(&port, &count)| (port, count))
            .collect();
        items.sort_by(|a, b| b.1.cmp(&a.1));

        let list_items: Vec<ListItem> = items
            .into_iter()
            .map(|(port, count)| ListItem::new(format!("Port {}: {} connections", port, count)))
            .collect();

        self.render_list(f, list_items, "Port Statistics", area, 2);
    }

    fn render_resolved_panel<B: Backend>(&self, f: &mut Frame<B>, area: ratatui::layout::Rect) {
        let mut items: Vec<(&IpAddr, &String)> = self.state.resolved_hosts.iter().collect();
        items.sort_by(|a, b| a.0.cmp(&b.0));

        let list_items: Vec<ListItem> = items
            .into_iter()
            .map(|(ip, hostname)| ListItem::new(format!("{}: {}", ip, hostname)))
            .collect();

        self.render_list(f, list_items, "Resolved Hosts", area, 3);
    }

    fn render_tree_panel<B: Backend>(&self, f: &mut Frame<B>, area: ratatui::layout::Rect) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let items: Vec<ListItem> = self
            .state
            .connection_tree
            .iter()
            .filter(|(source, _)| {
                self.source_filter.as_ref().map_or(true, |filter| {
                    regex::Regex::new(filter).map_or(false, |re| re.is_match(&source.to_string()))
                })
            })
            .flat_map(|(source, connections)| {
                let filtered_conns: Vec<&Connection> = connections
                    .iter()
                    .filter(|conn| self.matches_filters(conn))
                    .collect();

                if filtered_conns.is_empty() {
                    return Vec::new(); // Return empty vec instead of iterator
                }

                let (active_conns, _): (Vec<&Connection>, Vec<&Connection>) = filtered_conns
                    .iter()
                    .cloned()
                    .partition(|conn| self.is_active(conn.last_seen));

                let total_bytes: u64 = filtered_conns.iter().map(|conn| conn.bytes).sum();
                let active_count = active_conns.len();

                // Create vec of items instead of chaining iterators
                let mut items = Vec::new();
                items.push(ListItem::new(format!(
                    "Source: {} (Total: {}, Active: {})",
                    source,
                    self.format_bytes(total_bytes),
                    active_count
                )));

                // Add connection items
                items.extend(filtered_conns.into_iter().map(|conn| {
                    let age = now.saturating_sub(conn.last_seen);
                    let status = if age < 10 {
                        "🟢 ACTIVE".to_string()
                    } else {
                        format!("⚫ INACTIVE ({}s)", age)
                    };
                    ListItem::new(format!(
                        "  └─ {}:{} ({}) [{}]",
                        conn.destination,
                        conn.port,
                        self.format_bytes(conn.bytes),
                        status
                    ))
                }));

                items // Return Vec<ListItem> consistently
            })
            .collect();

        self.render_list(f, items, "Connection Tree", area, 4);
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let (tx, rx) = channel();
    let mut app = App::new(rx);

    // Get all available network devices
    let devices = Device::list().unwrap_or_default();

    // Spawn a capture thread for each device
    for device in devices {
        let tx_clone = tx.clone();
        thread::spawn(move || {
            if let Ok(cap) = Capture::from_device(device) {
                if let Ok(mut cap) = cap
                    .promisc(true)
                    .snaplen(96)
                    .buffer_size(16 * 1024 * 1024)
                    .timeout(1)
                    .open()
                {
                    loop {
                        match cap.next_packet() {
                            Ok(packet) => {
                                if let Some(conn) = process_packet(&packet) {
                                    let _ = tx_clone.send(Message::NewConnection(conn));
                                }
                            }
                            Err(pcap::Error::TimeoutExpired) => continue,
                            Err(_) => break,
                        }
                    }
                }
            }
        });
    }

    let tx_clone = tx.clone();
    thread::spawn(move || loop {
        thread::sleep(Duration::from_millis(200));
        let _ = tx_clone.send(Message::UpdateStats);
    });

    // In the main loop:
    loop {
        terminal.draw(|f| app.render(f))?;
        app.update();

        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    // First handle input mode keys
                    KeyCode::Enter if app.input_mode != InputMode::Normal => {
                        match app.input_mode {
                            InputMode::Source => {
                                app.source_filter = Some(app.input_value.clone());
                            }
                            InputMode::Destination => {
                                app.dest_filter = Some(app.input_value.clone());
                            }
                            _ => {}
                        }
                        app.input_mode = InputMode::Normal;
                        app.input_value.clear();
                    }
                    KeyCode::Esc if app.input_mode != InputMode::Normal => {
                        app.input_mode = InputMode::Normal;
                        app.input_value.clear();
                    }
                    // Handle input characters only in input mode
                    key if app.input_mode != InputMode::Normal => match key {
                        KeyCode::Char(c) => {
                            app.input_value.push(c);
                        }
                        KeyCode::Backspace => {
                            app.input_value.pop();
                        }
                        _ => {}
                    },
                    // Handle other keys only in normal mode
                    key if app.input_mode == InputMode::Normal => match key {
                        KeyCode::Char('q') => break,
                        KeyCode::Char('1') => app.active_panel = ActivePanel::Tcp,
                        KeyCode::Char('2') => app.active_panel = ActivePanel::Udp,
                        KeyCode::Char('3') => app.active_panel = ActivePanel::Ports,
                        KeyCode::Char('4') => app.active_panel = ActivePanel::ResolvedHosts,
                        KeyCode::Char('5') => app.active_panel = ActivePanel::Tree,
                        KeyCode::Char('s') => {
                            app.input_mode = InputMode::Source;
                            app.input_value.clear();
                        }
                        KeyCode::Char('d') => {
                            app.input_mode = InputMode::Destination;
                            app.input_value.clear();
                        }
                        KeyCode::Char('c') => {
                            app.source_filter = None;
                            app.dest_filter = None;
                        }
                        KeyCode::Up => app.scroll(Direction::Horizontal),
                        KeyCode::Down => app.scroll(Direction::Vertical),
                        _ => {}
                    },
                    _ => {}
                }
            }
        }

        if app.input_mode != InputMode::Normal {
            terminal.draw(|f| app.render(f))?; // Immediate redraw during input
        }
    }

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())
}

// Packet processing

fn process_packet(packet: &pcap::Packet) -> Option<Connection> {
    if let Some(ethernet) = EthernetPacket::new(packet.data) {
        if let Some(ip) = Ipv4Packet::new(ethernet.payload()) {
            match ip.get_next_level_protocol() {
                IpNextHeaderProtocols::Tcp => process_tcp_packet(&ip),
                IpNextHeaderProtocols::Udp => process_udp_packet(&ip),
                _ => None,
            }
        } else {
            None
        }
    } else {
        None
    }
}

fn process_tcp_packet(ip: &Ipv4Packet) -> Option<Connection> {
    TcpPacket::new(ip.payload()).map(|tcp| Connection {
        source: IpAddr::V4(ip.get_source()),
        destination: IpAddr::V4(ip.get_destination()),
        port: tcp.get_destination(),
        protocol: Protocol::Tcp,
        bytes: ip.get_total_length() as u64,
        last_seen: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}

fn process_udp_packet(ip: &Ipv4Packet) -> Option<Connection> {
    UdpPacket::new(ip.payload()).map(|udp| Connection {
        source: IpAddr::V4(ip.get_source()),
        destination: IpAddr::V4(ip.get_destination()),
        port: udp.get_destination(),
        protocol: Protocol::Udp,
        bytes: ip.get_total_length() as u64,
        last_seen: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    })
}
