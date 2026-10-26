"""Private finite process accounting; inherited FDs grant no execution authority.

Traditional POSIX record locks belong to a PID, not an inherited open-file
 description. Each process must keep one descriptor for this inode and enter
only from its owning thread. Closing any alias for the inode would release all
that PID's record locks. No aliases are created by this module.
"""
from __future__ import annotations

from contextlib import contextmanager
import errno
import fcntl
import hashlib
import os
import re
import select
import stat
import struct
import sys
import types
import tempfile
import threading
import time

MAGIC = b'WKOBUDG1'
VERSION = 1
HEADER = struct.Struct('>8sI32s5Q')
COUNTERS = struct.Struct('>3Q')
DIGEST_SIZE = 32
HEADER_SIZE = HEADER.size + DIGEST_SIZE
RECORD_SIZE = HEADER_SIZE + COUNTERS.size + DIGEST_SIZE
MAX_PROCESS_OUTPUT_BYTES = 64 * 1024**2
MAX_PROCESSES = 10000
MAX_TIMEOUT_NS = 3600 * 1_000_000_000
# Sibling scripts load this file with importlib under distinct names. One tiny
# process-local registry prevents two module instances/threads owning an inode.
_registry_name = '_wukongim_owned_budget_contexts_v1'
_candidate_registry = types.ModuleType(_registry_name)
_candidate_registry.lock = threading.Lock()
_candidate_registry.owners = set()
_REGISTRY = sys.modules.setdefault(_registry_name, _candidate_registry)


class BudgetError(ValueError):
    """Owned numeric state, identity, time or a finite grant is invalid."""


def require(condition, message):
    if not condition:
        raise BudgetError(message)


def _sha(raw):
    return hashlib.sha256(raw).digest()


def _write_all(fd, raw, offset):
    while raw:
        count = os.pwrite(fd, raw, offset)
        require(count > 0, 'owned budget write incomplete')
        raw, offset = raw[count:], offset + count


class SharedBudget:
    """One process/thread owns one FD; every grant uses a per-PID record lock."""

    @classmethod
    def create(cls, *, request_sha256, effect_deadline_ns, hard_deadline_ns,
               max_process_output_bytes, max_processes):
        require(isinstance(request_sha256, str) and re.fullmatch('[0-9a-f]{64}', request_sha256),
                'owned budget request digest invalid')
        now = time.monotonic_ns()
        require(type(effect_deadline_ns) is int and type(hard_deadline_ns) is int
                and now < effect_deadline_ns <= hard_deadline_ns
                and hard_deadline_ns - now <= MAX_TIMEOUT_NS, 'owned budget deadline invalid')
        require(type(max_process_output_bytes) is int and 0 < max_process_output_bytes <= MAX_PROCESS_OUTPUT_BYTES
                and type(max_processes) is int and 0 < max_processes <= MAX_PROCESSES,
                'owned process bounds invalid')
        header = HEADER.pack(MAGIC, VERSION, bytes.fromhex(request_sha256), now,
            effect_deadline_ns, hard_deadline_ns, max_process_output_bytes, max_processes)
        header += _sha(header)
        fd, name = tempfile.mkstemp(prefix='wk-owned-budget-')
        try:
            os.unlink(name)
            os.fchmod(fd, 0o600)
            os.set_inheritable(fd, False)
            _write_all(fd, header + cls._encoded_state(header, (0, 0, 0)), 0)
            return cls.attach(fd, expected_request_sha256=request_sha256)
        except Exception:
            os.close(fd)
            raise

    @classmethod
    def attach(cls, fd, *, expected_request_sha256):
        require(type(fd) is int and fd >= 0 and isinstance(expected_request_sha256, str)
                and re.fullmatch('[0-9a-f]{64}', expected_request_sha256), 'owned budget attachment invalid')
        try:
            metadata = os.fstat(fd)
            require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 0
                    and stat.S_IMODE(metadata.st_mode) == 0o600 and metadata.st_uid == os.getuid()
                    and metadata.st_size == RECORD_SIZE, 'owned budget descriptor invalid')
            raw = os.pread(fd, HEADER_SIZE, 0)
            require(len(raw) == HEADER_SIZE and _sha(raw[:-DIGEST_SIZE]) == raw[-DIGEST_SIZE:],
                    'owned budget header corrupt')
            values = HEADER.unpack(raw[:-DIGEST_SIZE])
            magic, version, request, started, effect, hard, max_output, max_processes = values
            require(magic == MAGIC and version == VERSION and request.hex() == expected_request_sha256
                    and 0 < started < effect <= hard and hard - started <= MAX_TIMEOUT_NS
                    and 0 < max_output <= MAX_PROCESS_OUTPUT_BYTES and 0 < max_processes <= MAX_PROCESSES,
                    'owned budget header differs')
            value = cls.__new__(cls)
            value._fd, value._identity, value._header = fd, (metadata.st_dev, metadata.st_ino), raw
            value._pid, value._thread, value._closed, value._locked_here = os.getpid(), threading.get_ident(), False, False
            value.request_sha256, value.started_ns = request.hex(), started
            value.effect_deadline_ns, value.hard_deadline_ns = effect, hard
            value.max_process_output_bytes, value.max_processes = max_output, max_processes
            value._registry_key = (value._pid, *value._identity)
            with _REGISTRY.lock:
                require(value._registry_key not in _REGISTRY.owners, 'owned budget already attached in this process')
                _REGISTRY.owners.add(value._registry_key)
            try:
                value.snapshot()
            except Exception:
                with _REGISTRY.lock:
                    _REGISTRY.owners.discard(value._registry_key)
                raise
            return value
        except (OSError, struct.error) as error:
            raise BudgetError('owned budget attachment failed') from error

    @staticmethod
    def _encoded_state(header, state):
        raw = COUNTERS.pack(*state)
        return raw + _sha(header + raw)

    def _owner(self):
        require(not self._closed and os.getpid() == self._pid
                and threading.get_ident() == self._thread, 'owned budget context differs')
        try:
            metadata = os.fstat(self._fd)
            require((metadata.st_dev, metadata.st_ino) == self._identity
                    and metadata.st_nlink == 0 and metadata.st_size == RECORD_SIZE,
                    'owned budget descriptor changed')
        except OSError as error:
            raise BudgetError('owned budget descriptor unavailable') from error

    @contextmanager
    def _record_lock(self, *, active, wait=True):
        self._owner()
        require(not self._locked_here, 'owned budget lock cannot be nested')
        deadline = self.effect_deadline_ns if active else self.hard_deadline_ns
        while True:
            try:
                fcntl.lockf(self._fd, fcntl.LOCK_EX | fcntl.LOCK_NB, RECORD_SIZE, 0, os.SEEK_SET)
                break
            except OSError as error:
                if error.errno not in (errno.EACCES, errno.EAGAIN):
                    raise BudgetError('owned budget lock failed') from error
                if not wait:
                    yield False
                    return
                remaining = (deadline - time.monotonic_ns()) / 1_000_000_000
                require(remaining > 0, 'owned budget lock deadline reached')
                select.select([], [], [], min(.002, remaining))
        self._locked_here = True
        try:
            yield True
        finally:
            self._locked_here = False
            try:
                fcntl.lockf(self._fd, fcntl.LOCK_UN, RECORD_SIZE, 0, os.SEEK_SET)
            except OSError as error:
                raise BudgetError('owned budget unlock failed') from error

    def _read_state(self):
        try:
            require(os.pread(self._fd, HEADER_SIZE, 0) == self._header, 'owned budget header changed')
            raw = os.pread(self._fd, COUNTERS.size + DIGEST_SIZE, HEADER_SIZE)
            require(len(raw) == COUNTERS.size + DIGEST_SIZE
                    and _sha(self._header + raw[:-DIGEST_SIZE]) == raw[-DIGEST_SIZE:],
                    'owned budget counter corrupt')
            state = COUNTERS.unpack(raw[:-DIGEST_SIZE])
            cancelled, output, processes = state
            require(cancelled in (0, 1) and output <= self.max_process_output_bytes
                    and processes <= self.max_processes, 'owned budget counter outside bounds')
            return state
        except (OSError, struct.error) as error:
            raise BudgetError('owned budget counter read failed') from error

    def _active(self, state):
        require(not state[0] and time.monotonic_ns() < self.effect_deadline_ns,
                'owned budget cancelled or deadline reached')

    def _grant(self, output, processes):
        with self._record_lock(active=True):
            cancelled, old_output, old_processes = state = self._read_state()
            self._active(state)
            require(old_output + output <= self.max_process_output_bytes
                    and old_processes + processes <= self.max_processes, 'owned process budget exceeded')
            next_state = (cancelled, old_output + output, old_processes + processes)
            try:
                _write_all(self._fd, self._encoded_state(self._header, next_state), HEADER_SIZE)
            except OSError as error:
                raise BudgetError('owned process reservation incomplete') from error
            return next_state

    def reserve_output(self, amount):
        """Reserve actual drained bytes without resetting a nested helper's total."""
        require(type(amount) is int and amount >= 0, 'owned output reservation invalid')
        return self._grant(amount, 0)[1]

    def reserve_process(self):
        """Reserve one owned child before spawning its fixed command."""
        return self._grant(0, 1)[2]

    def check(self):
        with self._record_lock(active=True):
            self._active(self._read_state())

    def remaining(self):
        self.check()
        value = (self.effect_deadline_ns - time.monotonic_ns()) / 1_000_000_000
        require(value > 0, 'owned budget deadline reached')
        return value

    def _cancel_state(self):
        require(time.monotonic_ns() < self.hard_deadline_ns, 'owned cancellation deadline reached')
        state = self._read_state()
        try:
            _write_all(self._fd, self._encoded_state(self._header, (1, state[1], state[2])), HEADER_SIZE)
        except OSError as error:
            raise BudgetError('owned cancellation write incomplete') from error

    def cancel(self):
        """Mark cancellation if attainable inside shutdown time; never needed to kill."""
        with self._record_lock(active=False):
            self._cancel_state()

    def try_cancel(self):
        """Try once without waiting; group termination never depends on this lock."""
        with self._record_lock(active=False, wait=False) as acquired:
            if not acquired:
                return False
            self._cancel_state()
            return True

    def snapshot(self):
        """Observe counters after cancellation/expiry; a busy expired lock refuses."""
        with self._record_lock(active=False):
            cancelled, output, processes = self._read_state()
        return dict(request_sha256=self.request_sha256, started_ns=self.started_ns,
            effect_deadline_ns=self.effect_deadline_ns, hard_deadline_ns=self.hard_deadline_ns,
            cancelled=bool(cancelled), max_process_output_bytes=self.max_process_output_bytes,
            max_processes=self.max_processes, process_output_bytes=output, processes_started=processes)

    def fileno(self):
        self._owner()
        return self._fd

    def close(self):
        if self._closed:
            return
        self._owner()
        require(not self._locked_here, 'cannot close owned budget while locked')
        self._closed = True
        try:
            os.close(self._fd)
        finally:
            with _REGISTRY.lock:
                _REGISTRY.owners.discard(self._registry_key)

    def __enter__(self):
        self._owner()
        return self

    def __exit__(self, *_unused):
        self.close()
