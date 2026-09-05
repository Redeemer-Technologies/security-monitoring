using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace net.redeemertech.Security
{
    internal sealed class ResponseByteCountingStream : Stream
    {
        private readonly Stream _innerStream;
        private long _bytesWritten;
        private bool _ignoreReplayPass;

        public ResponseByteCountingStream( Stream innerStream )
        {
            _innerStream = innerStream ?? throw new ArgumentNullException( nameof( innerStream ) );
        }

        public long BytesWritten => Interlocked.Read( ref _bytesWritten );

        // Integrated ASP.NET re-filters the native buffers after an explicit
        // PreSendRequestContent notification. Those bytes have already passed
        // this filter. Forward the replay without counting it a second time.
        internal void IgnoreNextFilteringPass()
        {
            _ignoreReplayPass = true;
        }

        public override bool CanRead => _innerStream.CanRead;

        public override bool CanSeek => _innerStream.CanSeek;

        public override bool CanWrite => _innerStream.CanWrite;

        public override long Length => _innerStream.Length;

        public override long Position
        {
            get => _innerStream.Position;
            set => _innerStream.Position = value;
        }

        public override void Flush()
        {
            _innerStream.Flush();
            _ignoreReplayPass = false;
        }

        public override async Task FlushAsync( CancellationToken cancellationToken )
        {
            await _innerStream.FlushAsync( cancellationToken ).ConfigureAwait( false );
            _ignoreReplayPass = false;
        }

        public override int Read( byte[] buffer, int offset, int count )
        {
            return _innerStream.Read( buffer, offset, count );
        }

        public override long Seek( long offset, SeekOrigin origin )
        {
            return _innerStream.Seek( offset, origin );
        }

        public override void SetLength( long value )
        {
            _innerStream.SetLength( value );
        }

        public override void Write( byte[] buffer, int offset, int count )
        {
            _innerStream.Write( buffer, offset, count );
            if ( !_ignoreReplayPass )
            {
                Interlocked.Add( ref _bytesWritten, count );
            }
        }

        public override async Task WriteAsync( byte[] buffer, int offset, int count, CancellationToken cancellationToken )
        {
            await _innerStream.WriteAsync( buffer, offset, count, cancellationToken ).ConfigureAwait( false );
            if ( !_ignoreReplayPass )
            {
                Interlocked.Add( ref _bytesWritten, count );
            }
        }

        public override void WriteByte( byte value )
        {
            _innerStream.WriteByte( value );
            if ( !_ignoreReplayPass )
            {
                Interlocked.Increment( ref _bytesWritten );
            }
        }

        protected override void Dispose( bool disposing )
        {
            if ( disposing )
            {
                _innerStream.Dispose();
            }

            base.Dispose( disposing );
        }
    }
}
