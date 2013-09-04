#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Python 2 and 3 compatibility utilities
import six

import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), '..', '..')))

# ===----------------------------------------------------------------------===

import gflags

gflags.DEFINE_string('host', u"localhost",
    u"Hostname or network address of RPC server",
    short_name='h')

gflags.DEFINE_integer('port', 8332,
    u"Network port of RPC server",
    short_name='P')
gflags.RegisterValidator('port',
    lambda rpcport: 1 <= rpcport <= 65535,
    message=u"Valid TCP/IP port numbers must be positive integers from 1 to 65535.")

gflags.DEFINE_string('sslcert', None,
    u"File containing server's public key. If specified, the connection must "
    u"be encrypted and the server's SSL certificate match.")

gflags.DEFINE_string('sslciphers',
    u"TLSv1+HIGH:!SSLv2:!aNULL:!eNULL:!AH:!3DES:@STRENGTH",
    u"Allowed SSL ciphers. See the OpenSSL documentation for syntax.")

gflags.DEFINE_string('username', None,
    u"Username for connection to RPC server",
    short_name='u')
gflags.MarkFlagAsRequired('username')

gflags.DEFINE_string('password', None,
    u"Username for connection to RPC server",
    short_name='p')
gflags.MarkFlagAsRequired('password')

gflags.DEFINE_integer('timeout', 15,
    u"Timeout for communication with RPC server, or zero to disable")
gflags.RegisterValidator('timeout',
    lambda timeout: 0 <= timeout,
    message=u"Valid timeout setting must be a positive number of seconds, or zero.")

from bitcoin.defaults import CHAIN_PARAMETERS

gflags.DEFINE_string('network', 'org.bitcoin.testnet3',
    u"Named index identifying bitcoin chain/network to connect to.")
gflags.RegisterValidator('network',
    lambda network: network in CHAIN_PARAMETERS,
    message=u"Unrecognized network name.")

# ===----------------------------------------------------------------------===

# SQLAlchemy object-relational mapper
from sqlalchemy import *
from sqlalchemy import orm
from sa_bitcoin import Base, core, ledger

class ConnectionStatistics(Base):
    __tablename__ = 'bitcoin_connection_statistics'
    __table_args__ = (
        Index('__'.join(['ix',__tablename__,'time_total']),    'time_total'),
        Index('__'.join(['ix',__tablename__,'time_database']), 'time_database'),
        Index('__'.join(['ix',__tablename__,'num_queries']),   'num_queries'),)

    info_id = Column(Integer,
        ForeignKey('bitcoin_connected_block_info.block_id'),
        primary_key = True)
    info = orm.relationship(lambda: core.ConnectedBlockInfo,
        backref = orm.backref('query_stats', uselist=False))

    time_total    = Column(Float, nullable=False)
    time_database = Column(Float, nullable=False)
    num_queries   = Column(Integer, nullable=False)

    table_stats = orm.relationship(lambda: ConnectionTableStatistics,
        order_by = lambda: ConnectionTableStatistics.name,
        lazy     = 'joined')

class ConnectionTableStatistics(Base):
    __tablename__ = 'bitcoin_connection_table_statistics'
    __table_args__ = (
        Index('__'.join(['ix',__tablename__,'query_stats_id','name']),
            'query_stats_id', 'name', unique = True),
        Index('__'.join(['ix',__tablename__,'num_inserts']), 'num_inserts'),
        Index('__'.join(['ix',__tablename__,'num_updates']), 'num_updates'),
        Index('__'.join(['ix',__tablename__,'num_deletes']), 'num_deletes'),)
    id = Column(Integer,
        Sequence('__'.join([__tablename__,'id','seq'])),
        primary_key = True)

    query_stats_id = Column(Integer,
        ForeignKey('bitcoin_connection_statistics.info_id'),
        nullable = False)
    query_stats = orm.relationship(lambda: ConnectionStatistics)

    name = Column(String(80), nullable=False)

    num_inserts = Column(Integer,
        CheckConstraint('0 <= num_inserts'),
        index = True, nullable = False)
    num_updates = Column(Integer,
        CheckConstraint('0 <= num_updates'),
        index = True, nullable = False)
    num_deletes = Column(Integer,
        CheckConstraint('0 <= num_deletes'),
        index = True, nullable = False)

from datetime import datetime
import threading
query_stats = threading.local()
def start_profile():
    global query_stats
    query_stats.num_queries   = 0
    query_stats.table_stats   = {}
    query_stats.time_database = 0.0
    query_stats.time_begin    = datetime.now()
def end_profile():
    global query_stats
    query_stats.time_total = (datetime.now() - query_stats.time_begin).total_seconds()
start_profile()

from sqlalchemy import event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Mapper
import logging
 
logging.basicConfig()
logger = logging.getLogger('utxoserv.sqltime')
logger.setLevel(logging.DEBUG)

@event.listens_for(Engine, 'before_cursor_execute')
def before_cursor_execute(conn, cursor, statement, 
                          parameters, context, executemany):
    global query_stats
    query_stats._begin = datetime.now()

@event.listens_for(Engine, 'after_cursor_execute')
def after_cursor_execute(conn, cursor, statement, 
                         parameters, context, executemany):
    global query_stats
    query_stats.num_queries += 1
    query_stats.time_database += (datetime.now() - query_stats._begin).total_seconds()

from recordtype import recordtype
TableStatistics = recordtype('TableStatistics',
    'num_inserts num_updates num_deletes'.split(), default=0)

@event.listens_for(Mapper, 'after_insert')
def after_insert(mapper, connection, target):
    global query_stats
    query_stats.table_stats.setdefault(target.__table__.name, TableStatistics())
    query_stats.table_stats[target.__table__.name].num_inserts += 1

@event.listens_for(Mapper, 'after_update')
def after_update(mapper, connection, target):
    global query_stats
    query_stats.table_stats.setdefault(target.__table__.name, TableStatistics())
    query_stats.table_stats[target.__table__.name].num_updates += 1

@event.listens_for(Mapper, 'after_delete')
def after_delete(mapper, connection, target):
    global query_stats
    query_stats.table_stats.setdefault(target.__table__.name, TableStatistics())
    query_stats.table_stats[target.__table__.name].num_deletes += 1

# ===----------------------------------------------------------------------===

from bitcoin.crypto import hash256
from bitcoin.merkle import merkle
from bitcoin.serialize import serialize_hash, deserialize_hash, deserialize_list
from bitcoin.tools import StringIO

def hash_string_to_integer(string, size=32):
    return deserialize_hash(StringIO(string.decode('hex')[::-1]), size)

def hash_integer_to_string(integer, size=32):
    return serialize_hash(integer, size)[::-1].encode('hex')

# ===----------------------------------------------------------------------===

from requests import HTTPError

class MissingBlockHeader(Exception):
    pass
class MissingTransaction(Exception):
    pass

def get_block(rpc, session, hash):
    block = session.query(core.Block).filter_by(hash=hash).first()
    if block is not None:
        return block, block.transactions

    try:
        hash_string = hash_integer_to_string(hash)
        block_dict = rpc.getblock(hash_string)
    except HTTPError:
        raise MissingBlockHeader(hash)

    kwargs = {}
    kwargs['version'] = int(block_dict['version'])
    if int(block_dict['height']) > 0:
        kwargs['parent_hash'] = hash_string_to_integer(block_dict['previousblockhash'])
    else:
        kwargs['parent_hash'] = 0
    kwargs['merkle_hash'] = hash_string_to_integer(block_dict['merkleroot'])
    kwargs['time']        = datetime.utcfromtimestamp(block_dict['time'])
    kwargs['bits']        = hash_string_to_integer(block_dict['bits'], 4)
    kwargs['nonce']       = int(block_dict['nonce'])
    block = core.Block(**kwargs)
    assert block.hash == hash

    for tx_hash_string in block_dict['tx']:
        tx_hash = hash_string_to_integer(tx_hash_string)
        tx = session.query(core.Transaction).filter_by(hash=tx_hash).first()
        if tx is None:
            try:
                tx_raw = rpc.getrawtransaction(tx_hash_string)
            except HTTPError:
                raise MissingTransaction(tx_hash)
            tx_file = StringIO(tx_raw.decode('hex'))
            tx = core.Transaction.deserialize(tx_file)
            assert not tx_file.read()
            assert tx.hash == tx_hash
        block.transactions.append(tx)

    session.add(block)
    session.flush()

    return block, block.transactions

def prune_output(txid_index, contract_index, hash, index):
    assert hash in txid_index
    coins = txid_index[hash]
    assert index in coins
    output = coins[index]

    del coins[index]
    if coins:
        txid_index[hash] = coins
    else:
        del txid_index[hash]

    contract_outpoint = ledger.ContractOutPoint(
        contract = output.contract,
        hash     = hash,
        index    = index)
    assert contract_outpoint in contract_index
    del contract_index[contract_outpoint]

class ParentNotConnected(Exception):
    pass

def connect_block(rpc, session, hash):
    block, transactions = get_block(rpc, session, hash)

    if block.info is not None:
        return block.info

    parent = session.query(core.Block).filter_by(hash=block.parent_hash).first()

    if parent is None:
        raise MissingBlockHeader(block.parent_hash)
    if parent.info is None:
        raise ParentNotConnected(block.parent_hash)

    start_profile()

    height = parent.info.height + 1

    txid_index = parent.info.txid_index.copy()
    contract_index = parent.info.contract_index.copy()

    for tx in transactions:
        assert tx.hash not in txid_index

        for input_ in tx.inputs:
            if not input_.is_coinbase:
                prune_output(txid_index, contract_index, input_.hash, input_.index)

        txid_index[tx.hash] = ledger.UnspentTransaction(transaction=tx)

        kwargs = {}
        kwargs['version'] = tx.version
        kwargs['coinbase'] = tx.is_coinbase
        kwargs['height'] = height
        if tx.version in (2,):
            kwargs['reference_height'] = tx.reference_height
        else:
            kwargs['reference_height'] = 0 # FIXME: we shouldn't need this
        for idx,output in enumerate(tx.outputs):
            if output.contract[:1] == six.int2byte(0x6a):
                continue
            contract_index[ledger.ContractOutPoint(
                contract = output.contract,
                hash     = tx.hash,
                index    = idx)] = ledger.OutputData(amount=output.amount, **kwargs)

    info = core.ConnectedBlockInfo(
        block          = block,
        parent         = parent,
        height         = height,
        aggregate_work = parent.info.aggregate_work + block.work,
        txid_index     = txid_index,
        contract_index = contract_index)

    session.add(info)
    session.flush()

    end_profile()

    global query_stats
    connection_statistics = ConnectionStatistics(
        info          = info,
        time_total    = query_stats.time_total,
        time_database = query_stats.time_database,
        num_queries   = query_stats.num_queries)

    for name in query_stats.table_stats:
        connection_statistics.table_stats.append(
            ConnectionTableStatistics(
                name        = name,
                num_inserts = query_stats.table_stats[name].num_inserts,
                num_updates = query_stats.table_stats[name].num_updates,
                num_deletes = query_stats.table_stats[name].num_deletes))

    session.add(connection_statistics)
    session.flush()

    return info

def load_chain(rpc, session):
    block_height = 1
    current_block = rpc.getblockcount()+1
    while block_height < current_block:
        block_hash_string = rpc.getblockhash(block_height)
        block_hash = hash_string_to_integer(block_hash_string)
        info = connect_block(rpc, session, block_hash)
        session.commit()

        print '\nAdded new block\n'
        print '  0x%064x' % block_hash
        print '    height: %d' % info.height
        print '  0x%064x' % info.txid_index.hash
        print '    transactions: %d' % len(info.txid_index)
        print '  0x%064x' % info.contract_index.hash
        print '    unspent outputs: %d' % len(info.contract_index)
        print '  total time: %f s' % info.query_stats.time_total
        print '  time in database: %f s' % info.query_stats.time_database
        print '  queries: %d' % info.query_stats.num_queries
        for table_stats in info.query_stats.table_stats:
            print '  %s' % table_stats.name
            print '    inserts: %d' % table_stats.num_inserts
            print '    updates: %d' % table_stats.num_updates
            print '    deletes: %d' % table_stats.num_deletes

        block_height = block_height + 1

import sys
if __name__ == '__main__':
    FLAGS = gflags.FLAGS
    try:
        argv = FLAGS(sys.argv)
    except gflags.FlagsError, e:
        print '%s\n\nUsage %s ARGS \n%s' % (e, sys.argv[0], FLAGS)
        sys.exit(1)

    kwargs = {}
    kwargs['username'] = FLAGS.username
    kwargs['password'] = FLAGS.password
    kwargs['timeout'] = FLAGS.timeout
    from bitcoin.rpc import Proxy
    rpc = Proxy('http://%s:%d/' % (FLAGS.host, FLAGS.port), **kwargs)

    engine = create_engine(
        os.environ.get('DATABASE_URL',
            FLAGS.network.replace('.', '-').join(['sqlite:///','.sqlite'])),
        echo = False)

    from sqlalchemy.orm import sessionmaker
    Session = sessionmaker(bind=engine)

    Base.metadata.create_all(engine)

    session = Session()

    chain = session.query(core.Chain).filter_by(name=FLAGS.network).first()
    if chain is None:
        parameters = CHAIN_PARAMETERS[FLAGS.network]

        chain = core.Chain(
            name               = FLAGS.network,
            magic              = parameters.magic,
            port               = parameters.port,
            genesis            = parameters.genesis[:80],
            genesis_hash       = hash256(parameters.genesis[:80]).intdigest(),
            testnet            = parameters.testnet,
            pubkey_hash_prefix = parameters.pubkey_hash_prefix,
            script_hash_prefix = parameters.script_hash_prefix,
            secret_prefix      = parameters.secret_prefix)

        session.add(chain)
        session.commit()

    genesis_block_hash_string = rpc.getblockhash(0)
    genesis_block_hash = hash_string_to_integer(genesis_block_hash_string)

    genesis_file = StringIO(CHAIN_PARAMETERS[FLAGS.network].genesis)
    genesis_block = core.Block.deserialize(genesis_file)
    genesis_transactions = list(deserialize_list(genesis_file, core.Transaction.deserialize))
    assert not genesis_file.read()

    for tx in genesis_transactions:
        genesis_block.transactions.append(
            session.query(core.Transaction).filter_by(hash=tx.hash).first() or tx)

    assert genesis_block.hash == genesis_block_hash
    assert genesis_block.merkle_hash == merkle(genesis_transactions)

    query = session.query(core.Block).filter_by(hash=genesis_block.hash)
    if query.count():
        genesis_block = query.first()
    else:
        session.add(genesis_block)
        session.commit()

    if genesis_block.info is None:
        genesis_block.info = core.ConnectedBlockInfo(
            parent         = None,
            height         = 0,
            aggregate_work = genesis_block.work,
            txid_index     = ledger.TxIdIndex(),
            contract_index = ledger.ContractIndex())

        session.add(genesis_block)
        session.commit()

    import IPython
    IPython.embed()

#
# End of File
#
