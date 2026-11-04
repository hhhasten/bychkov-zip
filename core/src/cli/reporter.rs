//! Progress reporting over stdout.

use bychkov_zip::archiver::Event;
use std::io::Write;

pub struct Reporter<W: Write> {
    out: W,
}

impl<W: Write> Reporter<W> {
    pub fn new(out: W) -> Self {
        Self { out }
    }

    pub fn event(&mut self, event: Event) {
        match event {
            Event::Status(stage) => self.line("byz-status:", stage.as_str()),
            Event::Progress(percent) => self.line("byz-progress:", &percent.to_string()),
        }
    }

    fn line(&mut self, prefix: &str, value: &str) {
        let _ = writeln!(self.out, "{prefix}{value}");
        let _ = self.out.flush();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bychkov_zip::archiver::Stage;

    #[test]
    fn writes_protocol_lines() {
        let mut output = Vec::new();
        let mut reporter = Reporter::new(&mut output);

        reporter.event(Event::Status(Stage::Analyzing));
        reporter.event(Event::Progress(42));
        reporter.event(Event::Status(Stage::Complete));

        assert_eq!(
            String::from_utf8(output).unwrap(),
            "byz-status:analyzing\nbyz-progress:42\nbyz-status:complete\n"
        );
    }
}
