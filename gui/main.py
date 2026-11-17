"""ESP32 Passive UART Protocol Analyzer v2.

Run: python -m pip install -r requirements.txt && python main.py
PyQt5 + pyqtgraph + pyserial. Observer USB must be configured to 921600.
"""
from __future__ import annotations

import csv
import json
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt5.QtGui import QColor, QFont, QBrush
from PyQt5.QtWidgets import (
    QApplication, QComboBox, QFileDialog, QGridLayout, QGroupBox,
    QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
    QMessageBox, QPlainTextEdit, QPushButton, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    QAbstractItemView, QSpinBox,
)
import pyqtgraph as pg
import serial
from serial.tools import list_ports
from activity import DataActivity
from protocol import decode_hex


class SerialReader(QThread):
    message = pyqtSignal(dict)
    failure = pyqtSignal(str)

    def __init__(self, port: str, baud: int):
        super().__init__()
        self.port = port
        self.baud = baud
        self.running = True
        self.device = None

    def run(self):
        try:
            self.device = serial.Serial(self.port, self.baud, timeout=0.2)
            while self.running:
                raw = self.device.read_until(b'\n', 4096)
                if not raw:
                    continue
                try:
                    event = json.loads(raw.decode('utf-8', errors='replace'))
                except json.JSONDecodeError:
                    continue
                if isinstance(event, dict) and 'event' in event:
                    self.message.emit(event)
        except (OSError, serial.SerialException) as exc:
            if self.running:
                self.failure.emit(str(exc))
        finally:
            if self.device is not None:
                try:
                    self.device.close()
                except Exception:
                    pass

    def stop(self):
        self.running = False
        self.wait(1700)


class Analyzer(QMainWindow):
    MAX_EVENTS = 80000
    MAX_VISIBLE = 1200

    def __init__(self):
        super().__init__()
        self.setWindowTitle('ESP32 | Passive UART Protocol Analyzer v2')
        self.resize(1460, 900)
        self.reader = None
        self.node_serial = {1: None, 2: None}
        self.events = deque()
        self.events_by_id = {}
        self.event_id = 0
        self.latest = {1: {}, 2: {}}
        self.summary = {}
        self.activity = DataActivity()
        self.replay_clock = None
        self.last_report = None
        self.baud_info = {1: {}, 2: {}}
        self.latency_ms = {1: float('nan'), 2: float('nan')}
        self.series = {name: deque(maxlen=180) for name in
                       ('time', 'wire_a', 'wire_b', 'pay_a', 'pay_b', 'rtt_a', 'rtt_b')}
        self.origin = time.monotonic()
        self.is_capturing = True
        self.replay_events = []
        self.replay_index = 0
        self.replay_timer = QTimer(self)
        self.replay_timer.timeout.connect(self.replay_step)
        self.build_ui()
        self.refresh_ports()
        self.chart_clock = QTimer(self)
        self.chart_clock.timeout.connect(self.redraw)
        self.chart_clock.start(1000)
        self.node_clock = QTimer(self)
        self.node_clock.timeout.connect(self.drain_node_logs)
        self.node_clock.start(150)

    def metric(self, title, key, grid, row, col):
        group = QGroupBox(title)
        lay = QVBoxLayout(group)
        label = QLabel('—')
        label.setObjectName('metric')
        label.setWordWrap(True)
        lay.addWidget(label)
        grid.addWidget(group, row, col)
        self.metrics[key] = label

    def build_ui(self):
        pg.setConfigOption('background', '#111c2d')
        pg.setConfigOption('foreground', '#d0d9e8')
        host = QWidget()
        self.setCentralWidget(host)
        root = QVBoxLayout(host)
        head = QLabel('ESP32  /  PASSIVE UART PROTOCOL ANALYZER')
        head.setObjectName('heading')
        root.addWidget(head)
        desc = QLabel('Bidirectional custom-frame analysis • independent hardware auto-baud • USB JSON capture')
        desc.setObjectName('subtitle')
        root.addWidget(desc)

        bar = QHBoxLayout()
        self.com = QComboBox()
        self.com.setMinimumWidth(105)
        self.usb_baud = QComboBox()
        self.usb_baud.addItems(['921600', '460800', '115200'])
        refresh = QPushButton('Refresh COMs')
        refresh.clicked.connect(self.refresh_ports)
        self.connect_button = QPushButton('Connect Observer')
        self.connect_button.clicked.connect(self.toggle_observer)
        self.capture_button = QPushButton('Pause Capture')
        self.capture_button.clicked.connect(self.toggle_capture)
        clear = QPushButton('Clear')
        clear.clicked.connect(self.clear_capture)
        save = QPushButton('Export CSV')
        save.clicked.connect(self.export_csv)
        save_json = QPushButton('Save JSONL')
        save_json.clicked.connect(self.export_jsonl)
        replay = QPushButton('Replay JSONL')
        replay.clicked.connect(self.open_replay)
        self.status = QLabel('● Disconnected')
        for widget in (QLabel('Observer COM'), self.com, QLabel('USB baud'), self.usb_baud,
                       refresh, self.connect_button, self.capture_button, clear, save,
                       save_json, replay, self.status):
            bar.addWidget(widget)
        root.addLayout(bar)

        metric_grid = QGridLayout()
        self.metrics = {}
        specs = [
            ('Observed DATA direction', 'direction'), ('Line 1 baud', 'baud_a'), ('Line 2 baud', 'baud_b'),
            ('A → B DATA', 'data_a'), ('B → A DATA', 'data_b'), ('CRC errors', 'crc'),
            ('A → B PDR proxy', 'pdr_a'), ('B → A PDR proxy', 'pdr_b'),
            ('Matched ACK', 'matched'), ('ACK timeouts', 'timeouts'),
            ('Avg ACK response', 'avg_rtt'), ('Observer state', 'observer_state'),
        ]
        for i, (title, key) in enumerate(specs):
            self.metric(title, key, metric_grid, i // 6, i % 6)
        self.metrics['direction'].setText('—')
        self.metrics['observer_state'].setText('Waiting')
        root.addLayout(metric_grid)

        self.tabs = QTabWidget()
        root.addWidget(self.tabs, 1)
        self.build_dashboard()
        self.build_inspector()
        self.build_controls()

        # Staged edition: underlying protocol stays compatible across releases.
        save.hide()
        save_json.hide()
        replay.hide()
        self.tabs.removeTab(2)
        self.tabs.removeTab(0)
        for label in self.metrics.values():
            label.parentWidget().hide()

        self.setStyleSheet('''
        QMainWindow,QWidget {background:#0b1220;color:#e2e8f0;font-size:12px}
        QLabel#heading {font-size:22px;font-weight:750;color:#7dd3fc;padding:5px 0}
        QLabel#subtitle {color:#94a3b8;padding-bottom:7px}
        QLabel#metric {font-size:19px;font-weight:750;color:#f8fafc}
        QGroupBox {border:1px solid #334155;border-radius:8px;margin-top:13px;padding:8px;background:#111c2d}
        QGroupBox::title {subcontrol-origin:margin;left:10px;padding:0 5px;color:#94a3b8}
        QPushButton,QComboBox,QLineEdit {background:#1e293b;color:#f8fafc;border:1px solid #475569;border-radius:6px;padding:7px}
        QPushButton:hover {background:#334155}
        QTabWidget::pane {border:1px solid #334155}
        QTabBar::tab {background:#172338;padding:9px 17px;color:#cbd5e1}
        QTabBar::tab:selected {background:#2563eb;color:white}
        QTableWidget {background:#101a2a;alternate-background-color:#172338;gridline-color:#334155}
        QHeaderView::section {background:#1e293b;color:#e2e8f0;padding:7px;border:0}
        QPlainTextEdit {background:#0d1725;color:#d0e1f4;border:1px solid #334155;border-radius:6px}
        ''')

    def build_dashboard(self):
        panel = QWidget()
        lay = QVBoxLayout(panel)
        self.direction_table = QTableWidget(2, 18)
        self.direction_table.setHorizontalHeaderLabels([
            'Direction', 'Baud', 'DATA', 'ACK sent', 'STATUS', 'CONTROL',
            'ACK matched', 'Timeout', 'ACK PDR proxy %', 'Seq gaps', 'Dup', 'CRC', 'Frame err',
            'Wire kbps', 'Payload kbps', 'Efficiency %', 'Avg RTT ms', 'ACK table full',
        ])
        self.direction_table.verticalHeader().setVisible(False)
        self.direction_table.setMaximumHeight(142)
        self.direction_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.direction_table.setAlternatingRowColors(True)
        self.direction_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        lay.addWidget(self.direction_table)

        self.wire_plot = self.make_plot('Observed wire throughput of valid frames + training sync (kbps)')
        self.payload_plot = self.make_plot('DATA payload throughput (kbps)')
        self.rtt_plot = self.make_plot('Last observed DATA → ACK response (ms, not one-way latency)')
        self.curves = {
            'wire_a': self.wire_plot.plot(pen=pg.mkPen('#38bdf8', width=2.4),
                                          symbol='o', symbolSize=4, name='A → B'),
            'wire_b': self.wire_plot.plot(pen=pg.mkPen('#f59e0b', width=2.2, style=Qt.DashLine),
                                          symbol='t', symbolSize=5, name='B → A'),
            'pay_a': self.payload_plot.plot(pen=pg.mkPen('#38bdf8', width=2.4), name='A → B'),
            'pay_b': self.payload_plot.plot(pen=pg.mkPen('#f59e0b', width=2.2, style=Qt.DashLine), name='B → A'),
            'rtt_a': self.rtt_plot.plot(pen=pg.mkPen('#38bdf8', width=2.4), name='A DATA → B ACK'),
            'rtt_b': self.rtt_plot.plot(pen=pg.mkPen('#f59e0b', width=2.2, style=Qt.DashLine), name='B DATA → A ACK'),
        }
        for graph in (self.wire_plot, self.payload_plot, self.rtt_plot):
            lay.addWidget(graph, 1)
        self.tabs.addTab(panel, 'Live Dashboard')

    @staticmethod
    def make_plot(title):
        chart = pg.PlotWidget(title=title)
        chart.addLegend()
        chart.setLabel('bottom', 'Elapsed capture time', units='s')
        chart.showGrid(x=True, y=True, alpha=0.2)
        return chart

    def build_inspector(self):
        panel = QWidget()
        lay = QVBoxLayout(panel)
        controls = QHBoxLayout()
        self.filter = QComboBox()
        self.filter.addItems(['All events', 'DATA', 'ACK', 'CONTROL', 'STATUS', 'CTRL_ACK',
                              'A → B', 'B → A', 'Errors', 'Baud events'])
        self.filter.currentIndexChanged.connect(self.rebuild_table)
        controls.addWidget(QLabel('Filter'))
        controls.addWidget(self.filter)
        controls.addStretch()
        lay.addLayout(controls)
        splitter = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 11)
        self.table.setHorizontalHeaderLabels([
            'PC time', 'Event', 'Line', 'Source', 'Destination', 'Protocol type',
            'Sequence', 'Payload len', 'Frame B', 'CRC', 'Detail',
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.itemSelectionChanged.connect(self.inspect_selected)
        self.raw_details = QPlainTextEdit()
        self.raw_details.setReadOnly(True)
        self.raw_details.setFont(QFont('Consolas', 10))
        self.raw_details.setPlainText('Click a captured frame to inspect its complete hexadecimal bytes, decoded fields and printable payload.')
        splitter.addWidget(self.table)
        splitter.addWidget(self.raw_details)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)
        lay.addWidget(splitter)
        self.tabs.addTab(panel, 'Packet Inspector + Hex')

    def build_controls(self):
        panel = QWidget()
        lay = QVBoxLayout(panel)
        title = QLabel('Optional direct USB controls for Node A and Node B')
        title.setObjectName('subtitle')
        lay.addWidget(title)
        hint = QLabel('Node USB console runs at 115200 even when the monitored UART baud changes. '
                      'Connect node COM ports separately from the Observer COM port. '
                      'BAUD= on either node coordinates both nodes through CONTROL / CTRL_ACK.')
        hint.setWordWrap(True)
        lay.addWidget(hint)
        line = QHBoxLayout()
        self.node_combos = {}
        self.node_buttons = {}
        for node in (1, 2):
            combo = QComboBox()
            button = QPushButton(f'Connect Node {"A" if node == 1 else "B"}')
            button.clicked.connect(lambda _=False, n=node: self.toggle_node(n))
            self.node_combos[node] = combo
            self.node_buttons[node] = button
            line.addWidget(QLabel('Node ' + ('A' if node == 1 else 'B') + ' USB COM'))
            line.addWidget(combo)
            line.addWidget(button)
        line.addStretch()
        lay.addLayout(line)
        self.payload_controls = {}
        for node, direction in ((1, 'A → B'), (2, 'B → A')):
            row = QHBoxLayout()
            mode = QComboBox()
            mode.addItems(['Random', 'Fixed'])
            size = QSpinBox()
            size.setRange(1, 256)
            size.setValue(64)
            size.setSuffix(' bytes')
            size.setEnabled(False)
            mode.currentIndexChanged.connect(lambda index, box=size: box.setEnabled(index == 1))
            self.payload_controls[node] = (mode, size)
            apply = QPushButton('Apply payload')
            apply.clicked.connect(lambda _, n=node: self.apply_payload(n))
            start = QPushButton('Start ' + direction)
            start.clicked.connect(lambda _, n=node: self.start_data(n))
            stop = QPushButton('Stop ' + direction)
            stop.clicked.connect(lambda _, n=node: self.write_commands(n, ['STOP']))
            for widget in (QLabel(direction + ' payload'), mode, size, apply, start, stop):
                row.addWidget(widget)
            row.addStretch()
            lay.addLayout(row)
        baud_row = QHBoxLayout()
        self.baud_node = QComboBox()
        self.baud_node.addItems(['Node A', 'Node B'])
        self.link_rate = QComboBox()
        self.link_rate.addItems(['9600', '19200', '38400', '57600', '115200'])
        self.link_rate.setCurrentText('115200')
        change = QPushButton('Change link baud')
        change.clicked.connect(lambda: self.write_commands(self.baud_node.currentIndex()+1,
                                                ['BAUD=' + self.link_rate.currentText()]))
        for widget in (QLabel('Request from'), self.baud_node, self.link_rate, change):
            baud_row.addWidget(widget)
        baud_row.addStretch()
        lay.addLayout(baud_row)
        self.node_console = QPlainTextEdit()
        self.node_console.setReadOnly(True)
        self.node_console.document().setMaximumBlockCount(400)
        lay.addWidget(self.node_console, 1)
        self.tabs.addTab(panel, 'Transmission Control')

    def refresh_ports(self):
        found = [p.device for p in list_ports.comports()]
        for combo in [self.com] + list(self.node_combos.values()):
            current = combo.currentText()
            combo.clear()
            combo.addItems(found)
            if current in found:
                combo.setCurrentText(current)

    def toggle_observer(self):
        if self.reader:
            self.disconnect_observer()
            return
        if not self.com.currentText():
            QMessageBox.warning(self, 'COM port', 'Connect the Observer and click Refresh COMs.')
            return
        self.replay_timer.stop()
        self.clear_capture()
        self.reader = SerialReader(self.com.currentText(), int(self.usb_baud.currentText()))
        self.reader.message.connect(self.receive_message)
        self.reader.failure.connect(self.observer_error)
        self.reader.start()
        self.connect_button.setText('Disconnect Observer')
        self.status.setText('● Connecting / waiting for JSON')

    def disconnect_observer(self):
        if self.reader:
            self.reader.stop()
            self.reader = None
        self.connect_button.setText('Connect Observer')
        self.last_report = None
        self.metrics['direction'].setText('—')
        self.status.setText('● Disconnected')

    def observer_error(self, message):
        self.disconnect_observer()
        QMessageBox.warning(self, 'Observer serial error', message + '\n\nClose Arduino Serial Monitor first.')

    def toggle_capture(self):
        self.is_capturing = not self.is_capturing
        self.capture_button.setText('Pause Capture' if self.is_capturing else 'Resume Capture')
        self.activity = DataActivity()
        self.metrics['direction'].setText('—')

    def receive_message(self, message):
        if not self.is_capturing:
            return
        event = message.get('event')
        self.status.setText('● Observer receiving JSON' if not self.replay_timer.isActive() else '● Replaying saved data')
        if event == 'ready':
            self.activity = DataActivity()
            self.metrics['observer_state'].setText('Auto-baud active')
        if event in ('baud_search', 'baud_lost', 'baud_failed', 'baud_detected'):
            line = int(message.get('line', 0))
            if line in (1, 2):
                self.baud_info[line] = message
                self.update_baud_metric(line)
        if event == 'stats':
            self.metrics['observer_state'].setText('Monitoring' if message.get('locked') else 'Auto-baud active')
            line = int(message.get('line', 0))
            if line in (1, 2):
                self.latest[line] = message
                self.update_direction_table()
                self.update_metrics()
        if event == 'summary':
            self.summary = message
            self.update_metrics()
        if event == 'latency':
            source = int(message.get('source', 0))
            if source in (1, 2):
                self.latency_ms[source] = float(message.get('latency_us', 0)) / 1000.0
        self.last_report = time.monotonic()
        observed_at = message.get('capture_s', self.last_report) if self.replay_timer.isActive() else self.last_report
        if self.replay_timer.isActive():
            self.replay_clock = observed_at
        self.activity.observe(message, observed_at)
        self.metrics['direction'].setText(self.activity.direction(observed_at))
        if event in ('ready', 'stats', 'summary', 'ack_capacity', 'frame', 'error', 'direction', 'latency', 'ack_timeout',
                     'baud_search', 'baud_lost', 'baud_failed', 'baud_detected'):
            self.add_capture(message)

    def update_baud_metric(self, line):
        info = self.baud_info[line]
        key = 'baud_a' if line == 1 else 'baud_b'
        event = info.get('event')
        if event == 'baud_detected':
            self.metrics[key].setText(f"{info.get('baud', '—')} detected")
        elif event == 'baud_failed':
            self.metrics[key].setText('Search retry')
        else:
            self.metrics[key].setText('Detecting…')

    def by_source(self):
        return {int(d.get('source', 0)): d for d in self.latest.values()
                if int(d.get('source', 0)) in (1, 2)}

    def update_metrics(self):
        src = self.by_source()
        a, b = src.get(1, {}), src.get(2, {})
        self.metrics['data_a'].setText(str(a.get('data', '—')))
        self.metrics['data_b'].setText(str(b.get('data', '—')))
        self.metrics['pdr_a'].setText(f"{float(a.get('pdr_pct', 0)):.1f}%" if a.get('data') and a.get('pdr_pct') is not None and not a.get('ack_capacity') else '—')
        self.metrics['pdr_b'].setText(f"{float(b.get('pdr_pct', 0)):.1f}%" if b.get('data') and b.get('pdr_pct') is not None and not b.get('ack_capacity') else '—')
        self.metrics['crc'].setText(str(sum(int(d.get('crc_errors', 0)) for d in self.latest.values())))
        matches = sum(int(d.get('matched_acks', 0)) for d in (a, b))
        self.metrics['matched'].setText(str(matches))
        timeouts = sum(int(d.get('ack_timeouts', 0)) for d in (a, b))
        self.metrics['timeouts'].setText(str(timeouts))
        self.metrics['avg_rtt'].setText('—')
        if self.summary.get('matched_acks') and self.summary.get('avg_latency_us') is not None:
            self.metrics['avg_rtt'].setText(f"{float(self.summary['avg_latency_us']) / 1000:.2f} ms")
        if not any(self.baud_info.values()):
            for line, key in ((1, 'baud_a'), (2, 'baud_b')):
                if self.latest[line].get('baud'):
                    self.metrics[key].setText(str(self.latest[line]['baud']) + ' configured')

    def update_direction_table(self):
        for row, source in enumerate((1, 2)):
            d = self.by_source().get(source, {})
            values = [
                'A → B' if source == 1 else 'B → A', (d.get('baud') or '—'),
                d.get('data', '—'), d.get('acks', '—'), d.get('status', '—'),
                d.get('controls', '—'), d.get('matched_acks', '—'), d.get('ack_timeouts', '—'),
                f"{float(d['pdr_pct']):.1f}" if d.get('data') and d.get('pdr_pct') is not None and not d.get('ack_capacity') else '—',
                d.get('seq_gaps', d.get('gaps', '—')), d.get('duplicates', '—'),
                d.get('crc_errors', '—'), d.get('framing_errors', '—'),
                f"{float(d['throughput_kbps']):.3f}" if d.get('locked', True) and d.get('throughput_kbps') is not None else '—',
                f"{float(d['payload_kbps']):.3f}" if d.get('locked', True) and d.get('payload_kbps') is not None else '—',
                f"{float(d['efficiency_pct']):.1f}" if d.get('wire_bytes') and d.get('efficiency_pct') is not None else '—',
                f"{float(d.get('avg_ack_rtt_us', 0)) / 1000:.2f}" if d.get('matched_acks') and d.get('avg_ack_rtt_us') is not None else '—',
                d.get('ack_capacity', '—'),
            ]
            for col, value in enumerate(values):
                self.direction_table.setItem(row, col, QTableWidgetItem(str(value)))

    def add_capture(self, obj):
        self.event_id += 1
        row = {'pc_time': datetime.now().strftime('%H:%M:%S.%f')[:-3],
               'capture_s': time.monotonic() - self.origin, **obj, 'id': self.event_id}
        self.events.append(row)
        self.events_by_id[self.event_id] = row
        if len(self.events) > self.MAX_EVENTS:
            dropped = self.events.popleft()
            self.events_by_id.pop(dropped['id'], None)
        if self.accept(row):
            self.add_table_row(row)

    def accept(self, row):
        choice = self.filter.currentText()
        event = row.get('event')
        typ = row.get('type')
        src = row.get('source')
        if choice == 'All events':
            return True
        if choice in ('DATA', 'ACK', 'CONTROL', 'STATUS', 'CTRL_ACK'):
            return event == 'frame' and typ == choice
        if choice == 'A → B':
            return event == 'frame' and src == 1
        if choice == 'B → A':
            return event == 'frame' and src == 2
        if choice == 'Errors':
            return event in ('error', 'ack_timeout', 'ack_capacity')
        return event in ('baud_search', 'baud_lost', 'baud_failed', 'baud_detected')

    def add_table_row(self, entry):
        table = self.table
        table.blockSignals(True)
        if table.rowCount() >= self.MAX_VISIBLE:
            table.removeRow(0)
        r = table.rowCount()
        table.insertRow(r)
        values = [
            entry.get('pc_time', ''), entry.get('event', ''), entry.get('line', ''),
            entry.get('source', ''), entry.get('destination', ''), entry.get('type', ''),
            entry.get('seq', ''), entry.get('length', ''), entry.get('frame_bytes', ''),
            'OK' if entry.get('crc_ok') else ('BAD' if entry.get('event') == 'error' else ''),
            entry.get('error', entry.get('baud', entry.get('latency_us', ''))),
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(str(value))
            if column == 0:
                item.setData(Qt.UserRole, entry['id'])
            if entry.get('event') == 'error':
                item.setForeground(QBrush(QColor('#fb7185')))
            table.setItem(r, column, item)
        table.blockSignals(False)
        table.scrollToBottom()

    def rebuild_table(self):
        self.table.setRowCount(0)
        for entry in list(self.events)[-self.MAX_VISIBLE:]:
            if self.accept(entry):
                self.add_table_row(entry)

    def inspect_selected(self):
        selected = self.table.selectedItems()
        if not selected:
            return
        idx = selected[0].row()
        index_item = self.table.item(idx, 0)
        if not index_item:
            return
        event = self.events_by_id.get(index_item.data(Qt.UserRole))
        if event is None:
            return
        text = ['OBSERVER JSON EVENT', json.dumps(event, indent=2, ensure_ascii=False)]
        raw = event.get('raw_hex')
        if raw:
            text.append('\nRAW BYTES\n' + ' '.join(raw[i:i + 2] for i in range(0, len(raw), 2)))
            try:
                fields = decode_hex(raw)
                text.extend(['\nDECODED FRAME',
                             f"START: 0x{fields['start']:02X}   NODE: {fields['node']}   TYPE: 0x{fields['type_byte']:02X} ({fields['frame_type']})",
                             f"SEQ: {fields['sequence']}   PAYLOAD LEN: {fields['payload_length']} B   FRAME: {fields['frame_bytes']} B",
                             f"CRC received: 0x{fields['crc_received']:04X}   CRC calculated: 0x{fields['crc_calculated']:04X}",
                             f"CRC OK: {fields['crc_ok']}   MARKERS OK: {fields['markers_ok']}",
                             '\nPAYLOAD HEX\n' + fields['payload_hex'],
                             '\nPAYLOAD ASCII\n' + fields['payload_ascii']])
                if fields['embedded_ip']:
                    text.append('\nSTRICT EMBEDDED IP DECODE\n' +
                                json.dumps(fields['embedded_ip'], indent=2))
                else:
                    text.append('\nProtocol: custom UART frame (no valid embedded IP packet detected)')
            except ValueError as exc:
                text.append(f'\nPartial/invalid frame: {exc}')
        self.raw_details.setPlainText('\n'.join(text))

    def redraw(self):
        if not self.is_capturing:
            return
        now = time.monotonic()
        if self.last_report is None or now - self.last_report > 3.5:
            self.metrics['direction'].setText('—')
            return
        self.metrics['direction'].setText(self.activity.direction(self.replay_clock if self.replay_clock is not None else now))
        t = round(time.monotonic() - self.origin, 2)
        src = self.by_source()
        a, b = src.get(1, {}), src.get(2, {})
        self.series['time'].append(t)
        for name, value in [
            ('wire_a', a.get('throughput_kbps') if a.get('locked', True) else None),
            ('wire_b', b.get('throughput_kbps') if b.get('locked', True) else None),
            ('pay_a', a.get('payload_kbps') if a.get('locked', True) else None),
            ('pay_b', b.get('payload_kbps') if b.get('locked', True) else None),
            ('rtt_a', self.latency_ms[1]),
            ('rtt_b', self.latency_ms[2]),
        ]:
            self.series[name].append(float(value) if value is not None else float('nan'))
        x = list(self.series['time'])
        for name, curve in self.curves.items():
            curve.setData(x, list(self.series[name]))

    def clear_capture(self):
        self.events.clear()
        self.events_by_id.clear()
        self.latest = {1: {}, 2: {}}
        self.summary = {}
        self.activity = DataActivity()
        self.replay_clock = None
        self.last_report = None
        self.latency_ms = {1: float('nan'), 2: float('nan')}
        self.baud_info = {1: {}, 2: {}}
        self.table.setRowCount(0)
        self.direction_table.clearContents()
        for series in self.series.values():
            series.clear()
        for curve in self.curves.values():
            curve.setData([], [])
        self.origin = time.monotonic()
        for key, value in self.metrics.items():
            value.setText('—')
        self.metrics['direction'].setText('—')
        self.metrics['observer_state'].setText('Waiting')

    def export_csv(self):
        if not self.events:
            QMessageBox.information(self, 'No data', 'Capture some events before exporting.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Export CSV', 'uart_capture.csv', 'CSV files (*.csv)')
        if not path:
            return
        fields = ['pc_time', 'event', 'ts_us', 'line', 'source', 'destination', 'type',
                  'seq', 'length', 'frame_bytes', 'wire_bytes', 'crc_ok', 'error',
                  'raw_hex', 'baud', 'measured', 'latency_us']
        try:
            with open(path, 'w', newline='', encoding='utf-8') as handle:
                writer = csv.DictWriter(handle, fieldnames=fields, extrasaction='ignore')
                writer.writeheader()
                writer.writerows(self.events)
        except OSError as exc:
            QMessageBox.warning(self, 'Export failed', str(exc))

    def export_jsonl(self):
        if not self.events:
            QMessageBox.information(self, 'No data', 'Nothing has been captured.')
            return
        path, _ = QFileDialog.getSaveFileName(self, 'Save JSONL', 'uart_capture.ndjson', 'JSON Lines (*.ndjson *.jsonl)')
        if not path:
            return
        try:
            with open(path, 'w', encoding='utf-8') as handle:
                for event in self.events:
                    handle.write(json.dumps({k: v for k, v in event.items() if k not in ('id', 'pc_time')}) + '\n')
        except OSError as exc:
            QMessageBox.warning(self, 'Save failed', str(exc))

    def open_replay(self):
        path, _ = QFileDialog.getOpenFileName(self, 'Replay JSONL', '', 'JSON Lines (*.ndjson *.jsonl)')
        if not path:
            return
        self.disconnect_observer()
        self.replay_timer.stop()
        rows = []
        try:
            with open(path, encoding='utf-8') as file:
                for line in file:
                    if not line.strip():
                        continue
                    row = json.loads(line)
                    if isinstance(row, dict) and row.get('event'):
                        rows.append(row)
                    if len(rows) >= 80000:
                        break
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, 'Replay failed', str(exc))
            return
        self.clear_capture()
        self.is_capturing = True
        self.capture_button.setText('Pause Capture')
        self.replay_events = rows
        self.replay_index = 0
        self.replay_timer.start(45)
        self.status.setText(f'● Replaying {Path(path).name}')

    def replay_step(self):
        if not self.is_capturing:
            return
        if self.replay_index >= len(self.replay_events):
            self.replay_timer.stop()
            self.status.setText('● Replay complete')
            return
        self.receive_message(self.replay_events[self.replay_index])
        self.replay_index += 1

    def toggle_node(self, node):
        if self.node_serial[node] is not None:
            self.disconnect_node(node)
            return
        port = self.node_combos[node].currentText()
        if not port:
            QMessageBox.warning(self, 'Node COM', 'Select a COM port first.')
            return
        try:
            self.node_serial[node] = serial.Serial(port, 115200, timeout=0, write_timeout=0.5)
        except (OSError, serial.SerialException) as exc:
            QMessageBox.warning(self, 'Node connection failed', str(exc))
            return
        self.node_buttons[node].setText(f'Disconnect Node {"A" if node == 1 else "B"}')
        self.node_console.appendPlainText(f'Opened Node {node} at {port} (USB 115200).')

    def disconnect_node(self, node):
        if self.node_serial[node]:
            try:
                self.node_serial[node].close()
            except (OSError, serial.SerialException):
                pass
            self.node_serial[node] = None
        self.node_buttons[node].setText(f'Connect Node {"A" if node == 1 else "B"}')

    def payload_command(self, node):
        mode, size = self.payload_controls[node]
        return 'MODE=RANDOM' if mode.currentIndex() == 0 else f'SIZE={size.value()}'

    def apply_payload(self, node):
        self.write_commands(node, [self.payload_command(node)])

    def start_data(self, node):
        self.write_commands(node, [self.payload_command(node), 'START'])

    def write_commands(self, node, commands):
        port = self.node_serial[node]
        if port is None:
            QMessageBox.warning(self, 'Node disconnected', f'Connect Node {"AB"[node-1]} first.')
            return
        message = ('\n'.join(commands) + '\n').encode('ascii')
        try:
            if port.write(message) != len(message):
                raise serial.SerialException('Incomplete USB command write')
            self.node_console.appendPlainText(f'→ Node {"AB"[node-1]}: ' + ', '.join(commands))
        except (OSError, serial.SerialException) as exc:
            self.node_console.appendPlainText(f'Command failed: {exc}')
            self.disconnect_node(node)

    def drain_node_logs(self):
        for node, dev in self.node_serial.items():
            if dev is None:
                continue
            try:
                data = dev.read(min(dev.in_waiting, 2048))
                if data:
                    self.node_console.appendPlainText(f'Node {node}: ' + data.decode('utf-8', errors='replace').rstrip())
            except (OSError, serial.SerialException) as exc:
                self.node_console.appendPlainText(f'Node {node} disconnected: {exc}')
                self.disconnect_node(node)

    def closeEvent(self, event):
        self.replay_timer.stop()
        self.disconnect_observer()
        for node in (1, 2):
            self.disconnect_node(node)
        event.accept()


def main():
    app = QApplication(sys.argv)
    pg.setConfigOptions(antialias=True)
    window = Analyzer()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
