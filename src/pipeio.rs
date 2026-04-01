/*
 * Nameto Oy © 2026. All rights reserved.
 *
 * This software is licensed under the GNU General Public License (GPL) version 3.
 * Commercial licensing options: <carrier-support@dnstele.com>.
 */

use std::io::{self, Write};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use tracing_subscriber::fmt::writer::MakeWriter;

#[derive(Clone, Debug, Default)]
pub(crate) struct DownstreamClosedState(Arc<AtomicBool>);

impl DownstreamClosedState {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.0.load(AtomicOrdering::SeqCst)
    }

    fn mark_closed(&self) {
        self.0.store(true, AtomicOrdering::SeqCst);
    }
}

pub(crate) struct BrokenPipeTolerantWriter<W> {
    inner: W,
    downstream_closed: DownstreamClosedState,
}

impl<W> BrokenPipeTolerantWriter<W> {
    pub(crate) fn new(inner: W) -> (Self, DownstreamClosedState) {
        let downstream_closed = DownstreamClosedState::new();
        (
            Self {
                inner,
                downstream_closed: downstream_closed.clone(),
            },
            downstream_closed,
        )
    }

    pub(crate) fn with_state(inner: W, downstream_closed: DownstreamClosedState) -> Self {
        Self {
            inner,
            downstream_closed,
        }
    }
}

pub(crate) struct BrokenPipeTolerantMakeWriter<M> {
    inner: M,
    downstream_closed: DownstreamClosedState,
}

impl<M> BrokenPipeTolerantMakeWriter<M> {
    pub(crate) fn new(inner: M) -> Self {
        Self {
            inner,
            downstream_closed: DownstreamClosedState::new(),
        }
    }
}

impl<'a, M> MakeWriter<'a> for BrokenPipeTolerantMakeWriter<M>
where
    M: MakeWriter<'a>,
{
    type Writer = BrokenPipeTolerantWriter<M::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        BrokenPipeTolerantWriter::with_state(
            self.inner.make_writer(),
            self.downstream_closed.clone(),
        )
    }
}

impl<W> Write for BrokenPipeTolerantWriter<W>
where
    W: Write,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.downstream_closed.is_closed() {
            return Ok(buf.len());
        }

        match self.inner.write(buf) {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.downstream_closed.mark_closed();
                Ok(buf.len())
            }
            other => other,
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.downstream_closed.is_closed() {
            return Ok(());
        }

        match self.inner.flush() {
            Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                self.downstream_closed.mark_closed();
                Ok(())
            }
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{BrokenPipeTolerantMakeWriter, BrokenPipeTolerantWriter, DownstreamClosedState};
    use std::io::{self, Write};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
    use tracing_subscriber::fmt::writer::MakeWriter;

    struct BrokenPipeOnFirstWrite {
        write_attempts: Arc<AtomicUsize>,
    }

    impl Write for BrokenPipeOnFirstWrite {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            let attempt = self.write_attempts.fetch_add(1, AtomicOrdering::SeqCst);
            if attempt == 0 {
                Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
            } else {
                Ok(buf.len())
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct OtherIoErrorWriter;

    impl Write for OtherIoErrorWriter {
        fn write(&mut self, _buf: &[u8]) -> io::Result<usize> {
            Err(io::Error::other("disk full"))
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    struct BrokenPipeOnFlush {
        flushed: Arc<AtomicUsize>,
    }

    impl Write for BrokenPipeOnFlush {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            self.flushed.fetch_add(1, AtomicOrdering::SeqCst);
            Err(io::Error::new(io::ErrorKind::BrokenPipe, "pipe closed"))
        }
    }

    #[test]
    fn broken_pipe_write_is_treated_as_downstream_closed() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let (mut writer, downstream_closed) =
            BrokenPipeTolerantWriter::new(BrokenPipeOnFirstWrite {
                write_attempts: Arc::clone(&attempts),
            });

        writer
            .write_all(b"first")
            .expect("broken pipe is tolerated");
        writer
            .write_all(b"second")
            .expect("subsequent writes are discarded");
        writer.flush().expect("flush succeeds after closure");

        assert!(downstream_closed.is_closed());
        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn non_broken_pipe_errors_are_propagated() {
        let (mut writer, downstream_closed): (BrokenPipeTolerantWriter<_>, DownstreamClosedState) =
            BrokenPipeTolerantWriter::new(OtherIoErrorWriter);

        let error = writer
            .write_all(b"payload")
            .expect_err("non-broken-pipe error remains fatal");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!downstream_closed.is_closed());
    }

    #[test]
    fn broken_pipe_flush_is_treated_as_downstream_closed() {
        let flushed = Arc::new(AtomicUsize::new(0));
        let (mut writer, downstream_closed) = BrokenPipeTolerantWriter::new(BrokenPipeOnFlush {
            flushed: Arc::clone(&flushed),
        });

        writer.write_all(b"payload").expect("write succeeds");
        writer.flush().expect("broken pipe flush is tolerated");

        assert!(downstream_closed.is_closed());
        assert_eq!(flushed.load(AtomicOrdering::SeqCst), 1);
    }

    #[test]
    fn tolerant_make_writer_shares_downstream_closed_state() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let make_writer = BrokenPipeTolerantMakeWriter::new({
            let attempts = Arc::clone(&attempts);
            move || BrokenPipeOnFirstWrite {
                write_attempts: Arc::clone(&attempts),
            }
        });

        let mut first = make_writer.make_writer();
        first.write_all(b"first").expect("broken pipe is tolerated");

        let mut second = make_writer.make_writer();
        second
            .write_all(b"second")
            .expect("subsequent writes are discarded");

        assert_eq!(attempts.load(AtomicOrdering::SeqCst), 1);
    }
}
