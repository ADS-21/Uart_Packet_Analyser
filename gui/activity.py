"""Direction of validated DATA observed during the last three seconds."""
class DataActivity:
    window = 3.0

    def __init__(self):
        self.last = {}

    def observe(self, event, now):
        source = event.get('source')
        if (event.get('event') == 'frame' and event.get('type') == 'DATA'
                and event.get('crc_ok') is True and source in (1, 2)
                and event.get('destination') == 3 - source):
            self.last[source] = now

    def direction(self, now):
        active = tuple(src for src in (1, 2)
                       if src in self.last and now - self.last[src] < self.window)
        return {(): 'Idle', (1,): 'A → B', (2,): 'B → A',
                (1, 2): 'Bidirectional'}[active]
