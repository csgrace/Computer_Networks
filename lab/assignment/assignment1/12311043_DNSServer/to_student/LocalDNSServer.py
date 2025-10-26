import queue
import threading
import socket
import time
import pickle
import os
from collections import OrderedDict
from queue import Queue, Empty
from dnslib import DNSRecord, QTYPE, RR, A, CNAME, DNSHeader, TXT
from dns import resolver, rdatatype, name as dns_name


class CacheManager:
    """
    --- Task 2. Automatic Cache Saving and Loading ---

    This class is responsible for managing all cache operations in the DNS server. It not only implements efficient in-memory caching,
    but also supports persisting the cache to a disk file, enabling state recovery after server restarts.

    Core features include:
    - Thread-safe design, ensuring data consistency under high-concurrency environments.
    - Automatic expiration based on TTL (Time to Live).
    - LRU (Least Recently Used) eviction policy, automatically removing the least recently accessed entries when the cache is full.
    - Automatically loading the cache file on server startup and saving it on shutdown.
    """

    def __init__(self, cache_file='dns_cache.pkl', max_size=200):
        """
        Initialize a CacheManager instance.

        This constructor sets the path and maximum capacity of the cache file,
        and immediately attempts to call `_load_from_file` to load existing cache from disk.
        """
        # TODO
        # Persistent cache file path and in-memory capacity (LRU enforced)
        self.cache_file = cache_file
        self.max_size = max_size
        # Re-entrant lock to allow nested calls if needed, and to protect cache integrity.
        self.lock = threading.RLock()
        # Load persisted cache (expired entries will be dropped during load).
        self.cache = self._load_from_file()
        print(f"Cache initialized with {len(self.cache)} entries")

    def _load_from_file(self):
        """
        --- Task 2.1 Load Cache from File ---

        At server startup, load and initialize the cache from a disk file.

        This method attempts to open the specified cache file and deserialize its data using pickle.
        Upon successful loading, it iterates through all cache entries and precisely removes any records
        that have expired during the server's downtime, based on their stored expiration timestamps,
        ensuring only valid cache entries are loaded into memory.

        :return:
            - collections.OrderedDict: If loading succeeds, returns an ordered dictionary containing valid cache entries.
            - collections.OrderedDict: If the file does not exist, is empty, or corrupted, returns a new empty ordered dictionary.
        """
        # TODO
        try:
            if not os.path.exists(self.cache_file):
                print("Cache file not found, starting with empty cache")
                return OrderedDict()
            with open(self.cache_file, 'rb') as f:
                raw_cache = pickle.load(f)
            now = time.time()
            cache = OrderedDict()
            loaded_count = 0
            expired_count = 0
            # Defensive: tolerate corrupted or unexpected structures.
            if isinstance(raw_cache, dict):
                for key, value in raw_cache.items():
                    try:
                        record, expire = value
                        rcode = getattr(record.header, "rcode", 0)
                        # only keep NOERROR (rcode == 0) and not expired
                        if expire > now and rcode == 0:
                            cache[key] = (record, expire)
                            loaded_count += 1
                        else:
                            expired_count += 1
                    except Exception:
                        # Skip malformed entries.
                        expired_count += 1
            print(f"Cache loaded: {loaded_count} valid entries, {expired_count} expired entries")
            return cache
        except Exception as e:
            # If anything fails, prefer a clean start rather than crashing the server.
            print(f"Failed to load cache: {e}, starting with empty cache")
            return OrderedDict()

    def save_to_file(self):
        """
        --- Task 2.2 Save Cache to File ---

        Persist all current in-memory cache entries to a disk file.

        This method is typically called when the server shuts down normally. It locks the cache,
        then uses pickle to serialize the entire in-memory `self.cache` ordered dictionary
        and writes it completely to the designated cache file.

        :return:
            - None: This function does not return a value.
        """
        # TODO
        with self.lock:
            try:
                with open(self.cache_file, 'wb') as f:
                    # Serialize the entire OrderedDict cache using pickle.
                    pickle.dump(self.cache, f)
                print(f"Cache saved with {len(self.cache)} entries")
            except Exception as e:
                print("Cache save failed:", e)

    def readCache(self, domain_name, qtype_str):
        """
        --- Task 2.3 Read Cache & Task 2.5 TTL (partial implementation) ---

        Retrieve a DNS record from the in-memory cache based on domain name and query type.

        This method is the core logic for reading from the cache. It first checks whether the requested record exists.
        If it does, it performs a critical TTL check: comparing the current time with the stored expiration timestamp.
        If the record has not expired, it returns the record; otherwise, it deletes the entry from the cache and returns None,
        triggering a new network query.

        :param domain_name: (str) The domain name being queried.
        :param qtype_str: (str) The record type being queried (e.g., "A", "CNAME").

        :return:
            - dnslib.DNSRecord: If a valid, unexpired cached record is found, return the record object.
            - None: If no such record exists in the cache or the record has expired, return None.
        """
        # TODO
        key = (domain_name.lower(), qtype_str)
        with self.lock:
            if key in self.cache:
                record, expire = self.cache[key]
                if time.time() < expire:
                    # LRU touch: mark as most recently used.
                    self.cache.move_to_end(key)
                    print(f"Cache hit for {domain_name} ({qtype_str})")
                    return record
                else:
                    # TTL expired: purge and behave like a miss.
                    del self.cache[key]
                    print(f"Cache expired for {domain_name} ({qtype_str})")
        return None

    def writeCache(self, domain_name, qtype_str, response_record):
        """
        --- Task 2.4 Write Cache & Task 2.5 TTL (partial implementation) ---

        Write a new DNS query result into the in-memory cache.

        This method is the core logic for writing to the cache. It first calculates the TTL from the DNS response
        and combines it with the current time to generate an absolute future "expiration timestamp". Then,
        it stores the DNS response record along with this timestamp as a unit in the cache. This method also handles
        negative caching (setting a fixed TTL for NXDOMAIN) and enforces the LRU eviction policy.

        :param domain_name: (str) The domain name that was queried.
        :param qtype_str: (str) The type of the queried record.
        :param response_record: (dnslib.DNSRecord) The complete DNS response object containing the data to be cached.

        :return:
            - None: This function does not return a value.
        """
        # TODO
        rcode = getattr(response_record.header, "rcode", 0)
        # cache only successful answers (NOERROR)
        if rcode != 0:
            print(f"Skip caching non-NOERROR response for {domain_name} ({qtype_str}), rcode={rcode}")
            return
        # Start with a safe default (300s).
        # If ANSWER exists, take the minimum TTL across all RRs to avoid serving stale components.
        key = (domain_name.lower(), qtype_str)
        if response_record.header.rcode == 3:
            ttl = 60
        else:
            ttl = 300
            try:
                if hasattr(response_record, 'rr') and response_record.rr:
                    for rr in response_record.rr:
                        if 0 < rr.ttl < ttl:
                            ttl = rr.ttl
            except Exception:
                pass

        expire = time.time() + ttl

        with self.lock:
            self.cache[key] = (response_record, expire)
            # Move to end to mark recent use (LRU discipline).
            self.cache.move_to_end(key)

            # LRU eviction: pop from the front until size is within limit.
            while len(self.cache) > self.max_size:
                removed_key = self.cache.popitem(last=False)
                print(f"Cache evicted: {removed_key[0]}")

            print(f"Cache updated for {domain_name} ({qtype_str}), TTL: {ttl}s")


class ReplyGenerator:
    """This class is used to generate various DNS response packets."""

    @staticmethod
    def replyForNotFound(income_record):
        header = DNSHeader(id=income_record.header.id, qr=1, rcode=3, ra=1)
        record = DNSRecord(header, q=income_record.q)
        return record

    @staticmethod
    def myReply(income_record, rr_list):
        response = DNSRecord(DNSHeader(id=income_record.header.id, qr=1, ra=1), q=income_record.q)
        for rr in rr_list:
            response.add_answer(rr)
        return response

    @staticmethod
    def replyForRedirect(income_record, redirect_ip, ttl=300):
        """
        --- Task 3.2 DNS Redirection (Response Construction) ---

        Construct a custom DNS response packet for DNS redirection functionality.

        When the server decides to redirect a domain name request to another IP address,
        this method generates a DNS response containing a "forged" A record. This response tells the client
        that the IP address corresponding to the queried domain is our specified `redirect_ip`.

        :param income_record: (dnslib.DNSRecord) The original DNS query request sent by the client.
                              We use it to retrieve the request ID and question section to ensure
                              the response can be correctly recognized by the client.
        :param redirect_ip: (str) The target IPv4 address to which the original domain should be redirected.
        :param ttl: (int, optional) The Time-To-Live for this forged A record, in seconds. Defaults to 300.
        :return:
            - dnslib.DNSRecord: A fully constructed DNS response object whose answer section
                                contains an A record pointing to `redirect_ip`.
        """
        # TODO
        # Build a DNS response with the original question, but with our chosen (forged) A record answer.
        header = DNSHeader(id=income_record.header.id, qr=1, ra=1)
        record = DNSRecord(header, q=income_record.q)
        # Create an answer section with a forged A record pointing to the redirect IP.
        rr = RR(rname=income_record.q.qname, rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(redirect_ip))
        record.add_answer(rr)
        return record


    @staticmethod
    def replyForBlocked(income_record, reason="Blocked due to security policy"):
        """
        --- Task 3.3 DNS Filtering (Response Construction) ---

        Construct a custom DNS response packet to explicitly refuse a query for a blocked domain.

        Instead of simply pretending the domain does not exist (NXDOMAIN), this method
        generates a response with a "Refused" status code (RCODE 5). This accurately
        informs the client that the query was intentionally denied due to a policy,
        which is a more precise and informative way to handle filtering.
        Optionally, it can include a TXT record to provide a human-readable reason for the block.

        :param income_record: (dnslib.DNSRecord) The original DNS query request sent by the client.
                              This is used to match the transaction ID and question section.
        :param reason: (str, optional) The reason for the block, which will be embedded in a
                                     TXT record in the answer section. If None, no TXT record is added.
        :return:
            - dnslib.DNSRecord: A DNS response object with a 'Refused' status code.
        """
        # TODO
        # Build a DNS response with RCODE=5 (Refused), echoing the original question.
        header = DNSHeader(id=income_record.header.id, qr=1, rcode=5, ra=1)
        record = DNSRecord(header, q=income_record.q)
        if reason:
            rr = RR(rname=income_record.q.qname, rtype=QTYPE.TXT, rclass=1, ttl=60, rdata=TXT(reason))
            record.add_answer(rr)
        return record


class DNSServer:
    """
    --- Task 1.2 DNSServer Implementation ---
    This class serves as the central coordinator of the entire DNS server, acting like an "air traffic controller".
    It does not perform the complex logic of DNS resolution itself, but instead manages the server's lifecycle,
    including startup, receiving client requests, dispatching tasks to worker threads (DNSHandler),
    collecting results, and sending final responses back to clients.

    To achieve high performance and concurrency, this class employs the classic multi-threaded "producer-consumer" model.
    """

    def __init__(self, source_ip, source_port, ip='127.0.0.1', port=5533, num_workers=20):
        """
        Initialize a DNSServer instance.

        This method sets up basic server configurations such as listening IP and port,
        creates the main socket required for network communication, and prepares the infrastructure for multi-threading.
        """
        # TODO: Initialize core components for multi-threading architecture.
        self.source_ip = source_ip
        self.source_port = source_port
        self.ip = ip
        self.port = port
        # UDP socket with SO_REUSEADDR for smoother restarts.
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Control flags and structures for the thread model.
        self.running = False
        self.request_queue = Queue()
        self.response_queue = Queue()
        self.num_workers = num_workers
        self.workers = []
        self.cache_manager = CacheManager()

    def start(self):
        """
        Start the full service of the DNS server.

        This method brings the server into active state, including binding the port, starting all background threads
        (receiver, sender, worker pool), and keeping the main thread waiting for shutdown signals.
        """
        # TODO
        self.running = True
        try:
            self.socket.bind((self.ip, self.port))
            print(f"Starting DNS server on {self.ip}:{self.port}")
            # Receiver thread: only reads datagrams and enqueues raw messages.
            self.receiver = threading.Thread(target=self._receive_loop, daemon=True, name="Receiver")
            self.receiver.start()
            # Sender thread: only dequeues and sends packed responses.
            self.sender = threading.Thread(target=self._send_loop, daemon=True, name="Sender")
            self.sender.start()
            # Worker pool: each worker parses, applies policy, uses cache, and resolves on cache miss.
            for i in range(self.num_workers):
                worker = DNSHandler(
                    self.source_ip,
                    self.source_port,
                    self.cache_manager,
                    self.request_queue,
                    self.response_queue,
                    worker_id=i
                )
                worker.daemon = True
                worker.start()
                self.workers.append(worker)
                print(f"Started worker thread {i}")

            print(f"DNS server started with {self.num_workers} workers")

            try:
                # Keep the main thread responsive to Ctrl+C while background threads do the work.
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nReceived interrupt signal, shutting down...")

        except Exception as e:
            # Startup failure should be surfaced but also trigger cleanup.
            print(f"Failed to start DNS server: {e}")
        finally:
            self.stop()


    def stop(self):
        """
        --- Task 1.2 stop method ---
        Gracefully shut down the server and perform necessary cleanup.
        """
        # TODO
        print("Shutting down DNS server...")
        self.running = False
        # Ask workers to exit by pushing sentinel tuples.
        try:
            for _ in self.workers:
                self.request_queue.put((None, None))
        except Exception:
            pass
        # Persist cache to disk (Task 2.2).
        if self.cache_manager:
            self.cache_manager.save_to_file()
        # Close the UDP socket to unblock receiver thread promptly.
        try:
            self.socket.close()
        except Exception:
            pass

        print("DNS server stopped")

    def _receive_loop(self):
        """
        --- Task 1.2 Receive Messages ---
        This method runs in a separate "receiver" thread, solely responsible for listening on the network port.
        """
        # TODO
        print("Receiver thread started")
        while self.running:
            try:
                # Block and wait for an incoming UDP packet (max DNS UDP size is 512 bytes for classic DNS).
                data, addr = self.socket.recvfrom(512)
                # Put the received (data, client address) tuple into the request queue for processing by worker threads.
                self.request_queue.put((data, addr))
            except socket.error as e:
                if self.running:
                    print(f"Socket error in receiver: {e}")
                break
            except Exception as e:
                if self.running:
                    print(f"Unexpected error in receiver: {e}")
        print("Receiver thread stopped")

    def _send_loop(self):
        """
        --- Task 1.2 Send Messages ---
        This method runs in a separate "sender" thread, solely responsible for sending responses.
        """
        # TODO
        print("Sender thread started")
        while self.running:
            try:
                addr, response = self.response_queue.get(timeout=1)
                # If both address and response are valid, send the DNS response back to the client via UDP.
                if addr and response:
                    self.socket.sendto(response, addr)
            except Empty:
                continue
            except socket.error as e:
                if self.running:
                    print(f"Socket error in sender: {e}")
            except Exception as e:
                if self.running:
                    print(f"Unexpected error in sender: {e}")
        print("Sender thread stopped")


class DNSHandler(threading.Thread):
    def __init__(self, source_ip, source_port, cache_manager, request_queue, response_queue, worker_id):
        super().__init__()
        self.source_ip = source_ip
        self.source_port = source_port
        # A small set of public resolvers for bootstrapping and fallback (Task 1.4/1.5).
        self.BOOTSTRAP_DNS_SERVERS = ['223.5.5.5', '119.29.29.29', '180.76.76.76', '8.8.8.8', '1.1.1.1']
        self.cache_manager = cache_manager
        self.request_queue = request_queue
        self.response_queue = response_queue
        self.worker_id = worker_id
        # Initialize root server IP at worker startup (Task 1.4).
        self.root_server_cache = self._initialize_root_server()

        # ==============================================================================
        # --- Example: DNS Redirection and Filtering Rules ---
        # ==============================================================================

        # --- 1. DNS Redirection Rules (redirect_map) ---
        #    This dictionary defines domains that should be "hijacked" and their target IP addresses.
        #    Key (key): The domain to match (lowercase, without trailing dot).
        #    Value (value): The IPv4 address string to return.
        self.redirect_map = {
            # Example 1: Redirect all queries for google.com to localhost (127.0.0.1).
            #           Often used for development or complete service blocking.
            "www.google.com": "127.0.0.1",
            "google.com": "127.0.0.1",

            # Example 2: Redirect a common ad-tracking domain to "0.0.0.0".
            #           "0.0.0.0" is an invalid, non-routable address.
            #           Clients will fail to connect, effectively blocking ads.
            "doubleclick.net": "0.0.0.0",
            "www.google-analytics.com": "0.0.0.0",

            # Example 3: "Friendly" redirection, e.g., map a memorable short domain to an IP.
            #           (for demonstration only)
            "friendly.name": "8.8.8.8"
            # "ads.annoying-tracker.com": "0.0.0.0",
        }

        # --- 2. DNS Filtering Rules (blocklist) ---
        #    This set defines domains to be completely blocked (blacklist).
        #    For any domain in this list, the server returns NXDOMAIN (domain does not exist).
        #    Using a set instead of a list provides O(1) lookup speed.


        self.blocklist = {
            # Example 1: Block known malware or phishing site domains.
            "malware-site.com",
            "phishing-attack.net",

            # Example 2: Block intrusive ad or tracking servers.
            "ads.annoying-tracker.com",
            "stats.unwanted-data-miner.org",

            # Example 3: Block specific sites you don't want users to access.
            "distracting-social-media.com"
        }
        # --- End of DNS Redirection and Filtering Rule Definitions ---
        # ==============================================================================

    def _initialize_root_server(self):
        try:
            server_ip, _ = self.queryRoot(self.source_ip, self.source_port)
            print(f"Worker {self.worker_id} initialized with root IP: {server_ip}")
            return server_ip
        except Exception as e:
            print(f"Worker {self.worker_id} failed to init root server: {e}. Using fallback.")
            return '198.41.0.4'  # a.root-servers.net

    def run(self):
        while True:
            try:
                message, address = self.request_queue.get()
                response_record = self.handle(message)
                if response_record:
                    self.response_queue.put((address, response_record.pack()))
            except Exception:
                pass


    def handle(self, message):
        """Handle a single DNS query, incorporating filtering and redirection logic."""

        try:
            income_record = DNSRecord.parse(message)
            # Normalize domain (strip trailing dot) and get query type name.
            domain_name = str(income_record.q.qname).strip('.')
            qtype_str = QTYPE[income_record.q.qtype]
            print(f"Worker {self.worker_id} handling query: {domain_name} ({qtype_str})")

            # --- Task 3.2 DNS Redirection Logic ---
            # After filtering, check if redirection is needed.
            # If the domain is in our redirect map, immediately build a response pointing to the new IP.
            # ==============================================================================
            # TODO
            if domain_name.lower() in self.redirect_map:
                redirect_ip = self.redirect_map[domain_name.lower()]
                print(f"Worker {self.worker_id} redirecting {domain_name} to {redirect_ip}")
                return ReplyGenerator.replyForRedirect(income_record, redirect_ip)

            # --- Task 3.2 END ---
            # ==============================================================================

            # --- Task 3.3 DNS Filtering Logic ---
            # This is where filtering is enforced. It runs before any other operation for maximum efficiency.
            # If the domain is in our blacklist, we immediately return a "does not exist" response.
            # ==============================================================================
            # TODO
            if domain_name.lower() in self.blocklist:
                print(f"Worker {self.worker_id} blocked (refused) domain: {domain_name}")
                return ReplyGenerator.replyForBlocked(income_record)
            # --- Task 3.3 END ---
            # ==============================================================================

            # ==============================================================================
            # --- Task 1.3 Core DNS Resolution Process ---
            # If the domain is neither filtered nor redirected, proceed with standard resolution.
            # This follows the strategy: "check cache first, then perform network query".
            # ==============================================================================
            # TODO
            # Cache first
            cached_record = self.cache_manager.readCache(domain_name, qtype_str)
            if cached_record is not None:
                print(f"Worker {self.worker_id} cache hit for {domain_name}")
                return cached_record

            # Cache miss — perform iterative resolution (with built-in upstream fallback).
            print(f"Worker {self.worker_id} cache miss for {domain_name}, performing iterative query")
            result_list = self.query(domain_name, income_record.q.qtype)

            if result_list:
                # Build a standard NOERROR response from the answer RRs.
                response = ReplyGenerator.myReply(income_record, result_list)
                # Cache successful response (TTL honored inside writeCache).
                self.cache_manager.writeCache(domain_name, qtype_str, response)
                return response
            else:
                # Last-resort sinkhole to avoid NXDOMAIN/timeouts from propagating to clients.
                print(f"Worker {self.worker_id} fallback sinkhole for {domain_name}")
                response = ReplyGenerator.replyForRedirect(income_record, "0.0.0.0", ttl=60)
                self.cache_manager.writeCache(domain_name, qtype_str, response)
                return response

        except Exception as e:
            print(f"Worker {self.worker_id} handle error: {e}")
            try:
                return ReplyGenerator.replyForRedirect(DNSRecord.parse(message), "0.0.0.0", ttl=60)
            except Exception:
                hdr = DNSHeader(id=0, qr=1, rcode=3, ra=1)
                return DNSRecord(hdr)
            # --- Task 1.3 END ---
            # ==============================================================================(self, message):



    def query(self, query_name, qtype):
        """
        --- Task 1.5 Iterative Query Implementation ---
        This method is the core resolution engine of the local DNS server. When a query cannot be found in the cache,
        this method simulates a DNS client's behavior, starting from the root server, following the DNS hierarchy,
        and progressively "asking for directions" until it finds the authoritative DNS server responsible for the domain
        and obtains the final answer.

        :param query_name: (str) The domain name to resolve, e.g., "www.google.com".
        :param qtype: (int) The record type to query, e.g., dnslib.QTYPE.A.

        :return:
            - list: On success, returns a list of one or more dnslib.RR objects.
                    This list may include CNAME and final A records.
            - None: On failure (due to non-existent domain, timeout, or error), returns None.
        """
        # TODO
        # Fast path: Try system resolver and public DNS for quick answer
        try:
            qtype_name_fast = QTYPE[qtype] if isinstance(qtype, int) else qtype
        except Exception:
            qtype_name_fast = 'A'
        if qtype_name_fast == 'A':
            # Try system resolver first (local OS DNS)
            try:
                r = resolver.Resolver(configure=True)
                r.timeout = 1.5
                r.lifetime = 3.0
                ans = r.resolve(query_name.rstrip('.'), 'A', raise_on_no_answer=False)
                rr_list = []
                if ans and ans.rrset:
                    ttl = ans.rrset.ttl or 300
                    for item in ans.rrset:
                        ip = item.address
                        rr_list.append(
                            RR(rname=query_name.rstrip('.') + '.', rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(ip)))
                    if rr_list:
                        return rr_list
            except Exception as e:
                print(f"[Fast System DNS] Failed for {query_name}: {e}")
            # Try several public DNS servers (fallback)
            for ns in self.BOOTSTRAP_DNS_SERVERS[:3]:
                try:
                    r = resolver.Resolver(configure=False)
                    r.nameservers = [ns]
                    r.timeout = 2.0
                    r.lifetime = 3.0
                    ans = r.resolve(query_name.rstrip('.'), 'A', raise_on_no_answer=False)
                    rr_list = []
                    if ans and ans.rrset:
                        ttl = ans.rrset.ttl or 300
                        for item in ans.rrset:
                            ip = item.address
                            rr_list.append(
                                RR(rname=query_name.rstrip('.') + '.', rtype=QTYPE.A, rclass=1, ttl=ttl, rdata=A(ip)))
                        if rr_list:
                            return rr_list
                except Exception as e:
                    print(f"[Fast Public DNS] Failed for {query_name} via {ns}: {e}")
                    continue

        #  Iterative resolution: start from root, follow referrals, retry for robustness
        current_servers = [self.root_server_cache] if hasattr(self,
                                                              'root_server_cache') and self.root_server_cache else list(
            self.BOOTSTRAP_DNS_SERVERS)
        tried = set()
        qname = query_name.rstrip('.')
        qtype_num = qtype
        max_hops = 16
        cname_chain = []
        hop = 0
        while hop < max_hops:
            hop += 1
            next_servers = []
            saw_cname = False
            for server_ip in current_servers:
                if not server_ip or server_ip in tried:
                    continue
                tried.add(server_ip)
                # UDP retry logic (5 tries per server, increased timeout for robustness)
                success = False
                for attempt in range(5):  # Up to 5 tries per server
                    try:
                        query = DNSRecord.question(qname, QTYPE[qtype_num] if isinstance(qtype_num, int) else qtype_num)
                        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        sock.settimeout(3.0 + attempt)  # 3.0s, 4.0s, ..., 7.0s
                        try:
                            sock.sendto(query.pack(), (server_ip, 53))
                            data, _ = sock.recvfrom(4096)
                        finally:
                            sock.close()
                        response = DNSRecord.parse(data)
                        success = True
                        break
                    except socket.timeout:
                        print(f"[Iterative] Timeout for {server_ip} on attempt {attempt + 1} (hop {hop})")
                        continue
                    except Exception as e:
                        print(f"[Iterative] Error querying {server_ip} on attempt {attempt + 1} (hop {hop}): {e}")
                        continue
                if not success:
                    print(f"[Iterative] All attempts failed for {server_ip} (hop {hop}); trying next server.")
                    continue
                # Parse DNS response
                if response.rr:
                    rr_list = []
                    cname_next = None
                    for rr in response.rr:
                        if rr.rtype == QTYPE.A:
                            rr_list.append(rr)
                        elif rr.rtype == QTYPE.CNAME:
                            cname_next = str(rr.rdata).rstrip('.')
                            rr_list.append(rr)
                        else:
                            rr_list.append(rr)
                    # If got at least one A record, return result (prepend CNAME chain if exists)
                    if any(r.rtype == QTYPE.A for r in rr_list):
                        if cname_chain:
                            rr_list = cname_chain + rr_list
                        return rr_list
                    # If CNAME found, restart walk for the CNAME target
                    if cname_next:
                        cname_chain.extend(rr_list)
                        qname = cname_next
                        saw_cname = True
                        break
                # If no answer: check authority section for NS/SOA
                ns_names = []
                for rr in response.auth:
                    if rr.rtype == QTYPE.NS:
                        ns_names.append(str(rr.rdata).rstrip('.').lower())
                    elif rr.rtype == QTYPE.SOA:
                        print(f"[Iterative] SOA found for {qname} (hop {hop}), negative response.")
                        return None
                # Find glue A records for NS hosts in additional section
                glue_ips = {}
                for rr in response.ar:
                    if rr.rtype == QTYPE.A:
                        glue_ips[str(rr.rname).rstrip('.').lower()] = str(rr.rdata)
                next_servers = []
                if ns_names:
                    # Prefer glue records
                    for ns in ns_names:
                        if ns in glue_ips:
                            next_servers.append(glue_ips[ns])
                            break
                    if not next_servers:
                        # Fallback: resolve NS names using domestic DNS (no domain restriction) and then system DNS
                        for ns in ns_names:
                            resolved_ip = None
                            try:
                                r114 = resolver.Resolver(configure=False)
                                r114.nameservers = ["114.114.114.114", "223.5.5.5", "119.29.29.29"]
                                r114.timeout = 3.0
                                r114.lifetime = 5.0
                                answers = r114.resolve(ns, 'A', lifetime=5.0)
                                for a in answers:
                                    resolved_ip = a.to_text()
                                    next_servers.append(resolved_ip)
                                    break
                            except Exception as e:
                                print(f"[Glue Fallback] Domestic DNS failed for NS {ns}: {e}")
                            if not resolved_ip:
                                try:
                                    answers = resolver.resolve(ns, 'A', lifetime=5)
                                    for a in answers:
                                        next_servers.append(a.to_text())
                                        break
                                except Exception as e:
                                    print(f"[Glue Fallback] System DNS failed for NS {ns}: {e}")
            if saw_cname:
                # CNAME: restart server list from root/TLD
                current_servers = [self.root_server_cache] if hasattr(self,
                                                                      'root_server_cache') and self.root_server_cache else list(
                    self.BOOTSTRAP_DNS_SERVERS)
                tried = set()
                continue
            if next_servers:
                # Deduplicate next_servers
                current_servers = list(dict.fromkeys(next_servers))
                tried = set()
                continue
            break
        # Failed after all hops
        print(f"[Final] Query failed for {query_name}, returning None.")
        return None


    def queryRoot(self, source_ip, source_port):
        """
        --- Task 1.4 Robust Dynamic Discovery of Root Server IP ---

        Dynamically and reliably discover the IP address of a currently available root DNS server.

        The iterative DNS query of a local DNS server must start from a root server. However, root server IPs may change
        or become inaccessible due to DNS pollution. This method queries a preset list of reliable public DNS servers
        to dynamically obtain a valid root server IP, serving as the "starting point" for all subsequent queries.

        :param source_ip: (str) Source IP address to use for this bootstrap query.
        :param source_port: (int) Source port to use for this bootstrap query.

        :return:
            - tuple: On success, returns (root_ip, root_ns_name), where:
                - root_ip (str): IPv4 address of a root server.
                - root_ns_name (str): Domain name of that root server.

        :raises Exception: If none of the preset public DNS servers can return a root server IP.
        """
        # TODO
        for dns_server in self.BOOTSTRAP_DNS_SERVERS:
            try:
                print(f"Worker {self.worker_id} querying {dns_server} for root servers")

                # Use string 'NS' to satisfy dnslib requirements for qtype.
                query = DNSRecord.question('.', 'NS')
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(4.0)

                try:
                    sock.sendto(query.pack(), (dns_server, 53))
                    data, _ = sock.recvfrom(4096)
                finally:
                    sock.close()

                response = DNSRecord.parse(data)

                # Pick the first NS and resolve its A using the same upstream DNS.
                for rr in response.rr:
                    if rr.rtype == QTYPE.NS:
                        ns_domain = str(rr.rdata).rstrip('.')
                        print(f"Worker {self.worker_id} found root NS: {ns_domain}")

                        ns_q = DNSRecord.question(ns_domain, 'A')
                        s2 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s2.settimeout(3.0)
                        try:
                            s2.sendto(ns_q.pack(), (dns_server, 53))
                            data2, _ = s2.recvfrom(4096)
                        finally:
                            s2.close()

                        resp2 = DNSRecord.parse(data2)
                        for ns_rr in resp2.rr:
                            if ns_rr.rtype == QTYPE.A:
                                root_ip = str(ns_rr.rdata)
                                print(f"Worker {self.worker_id} resolved {ns_domain} to {root_ip}")
                                return root_ip, ns_domain

            except Exception as e:
                # Try the next upstream if this one fails.
                print(f"Worker {self.worker_id} failed to get root from {dns_server}: {e}")
                continue
        # Fallback to a small hardcoded set of root servers if dynamic discovery fails entirely.
        fallback_roots = [
            ('198.41.0.4', 'a.root-servers.net'),
            ('199.9.14.201', 'b.root-servers.net'),
            ('192.33.4.12', 'c.root-servers.net')
        ]
        for ip, name in fallback_roots:
            print(f"Worker {self.worker_id} using fallback root: {name} ({ip})")
            return ip, name

        # Ultimate fallback (should rarely be hit).
        return '198.41.0.4', 'a.root-servers.net'


def get_local_ip():
    """
    --- Task 1.1 Automatically Detect Outbound Interface IP ---
    When performing network communication, especially on machines with multiple interfaces (Ethernet, Wi-Fi, VPN),
    the program needs to know which IP to use as the source so that response packets are correctly routed back.
    This function aims to automatically discover this "best" outbound IP address.

    :return:
        - str: On success, returns the local IP address as a string (e.g., '192.168.1.100').
        - str: On failure (e.g., no network, firewall), returns a robust fallback '0.0.0.0'.
    """
    # TODO
    # Heuristic: a UDP "connect" to 8.8.8.8:53 sends no packets but binds a local address; we read that chosen outbound IP.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 53))
            local_ip = s.getsockname()[0]
            return local_ip
    except Exception:
        return '0.0.0.0'

if __name__ == '__main__':
    source_ip = get_local_ip()
    print(f"Automatically detected local IP address: {source_ip}")
    print(f"Local DNS Server Starting...")
    print(f"Local IP: {source_ip}")
    print(f"Listening on port: 5533")
    print(f"Workers: 20")
    print("Press Ctrl+C to stop the server")
    print("-" * 50)
    local_dns_server = DNSServer(source_ip, source_port=0, num_workers=20)
    local_dns_server.start()
