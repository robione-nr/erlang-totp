-module(totp).
-behaviour(gen_server).
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, 
         code_change/3, start_link/0, start_link/1]).

-define(KEY,{base32,<<"GT7MA25HHANZX7SWQ3======">>}).

-define(NTP_IPADDR,{216,239,35,0}).
-define(NTP_EPOCH_OFFSET,2208988800).
-define(MTU, 1500).
-define(NTP_PORT, 123).
-define(PORT_RANGE, 16384).
-define(MAX_PORT, 65535).
-define(USEC_FRAC(A), A/1000000*4294967296).
-define(USEC_INT(A), A/4294967296*1000000).

%% ====================================================================
%% API functions
%% ====================================================================
-export([validate/1]).

validate(Pin) -> gen_server:call(?MODULE, {validate, Pin}).

%% ====================================================================
%% Behavioural functions
%% ====================================================================
start_link() -> start_link([]).
start_link(Args) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, Args, []).

%% init/1
%% ====================================================================
init([]) ->
    TestA = lists:keyfind(crypto, 1, application:loaded_applications()),
    TestB = case code:load_file(base32) of
                {module,base32} -> ok;
                {error, not_purged} -> ok;
                _ -> false
            end,
    
    if (TestA =/= false) andalso (TestB =/= false) ->
        Key = case ?KEY of
            {plaintext,K} when is_binary(K) -> K;
            {base32, K} when is_binary(K) -> base32:decode(K);
            {base64, K} when is_binary(K) -> base64:decode(K)
        end,
    
        self() ! synctime,
        
        {ok, _} = timer:send_interval(30000,self(),update_pins),
        {ok, _} = timer:send_interval(86400000,self(),synctime),
        
        Step = generate_timestep(),
        {ok, {[totp(Key, Step-1), totp(Key, Step), totp(Key, Step+1)], Key, 0}};
    true ->
        {error,{dependencies,[crypto, base32]}}
    end.


%% handle_call/3
%% ====================================================================
handle_call({validate, Pin}, _, {Pins, _, _} = State) ->
    %% Rate limiting handled prior to this point in YAWS
    {reply, lists:member(Pin, Pins), State};
handle_call(_, _, State) ->
    {reply, {error, invalid_arg}, State}.


%% handle_info/2
%% ====================================================================
handle_info(update_pins , {[_|Pins], Key, Offset}) ->
    NewPins = lists:append(Pins, [totp(Key, generate_timestep(Offset)+1)]),
    {noreply,{NewPins, Key, Offset}};
handle_info({update_offset, NewOffset} , {Pins, Key, _}) ->
    {noreply,{Pins, Key, NewOffset}};
handle_info(synctime, State) ->
    spawn(?MODULE, sync_time, [self()]),
    {noreply, State};
handle_info(_, State) ->
    {noreply, State}.

%% ====================================================================
%% Internal functions
%% ====================================================================

sync_time(Pid) ->
    <<_:24/binary, T1:64/integer-unsigned, _/binary>> = Packet = 
prepare_ntp_request(),

    {ok, Socket} = find_udp_socket(),
    ok = gen_udp:send(Socket, ?NTP_IPADDR, ?NTP_PORT, Packet),
    {ok, {?NTP_IPADDR, ?NTP_PORT, <<Data:48/binary , Tail/binary>>}} = 
gen_udp:recv(Socket, ?MTU, 3000),

    <<T4:64/integer-unsigned>> = client_ntp_timestamp(),
    <<_:32/binary, T2:64/integer-unsigned, T3:64/integer-unsigned>> = Data,
    
    <<Offset:32/integer, _/binary>> = <<(((T2-T1) + (T3-T4)) div 
                                           2):64/integer-unsigned>>,

    if size(Tail) =:= 12 ->
            <<Key:4/binary, Sig:8/binary>> = Tail,
            Test = crypto:hash(md5, <<Key:4/binary, Data:48/binary>>),
                    
            if Test =:= Sig ->  Pid ! {update_offset, Offset};
            true ->             Pid ! {update_offset, transmission_error}
            end;
    true ->         Pid ! {update_offset, Offset}
    end.
    
find_udp_socket() ->
    Attempt = round(?MAX_PORT - (?PORT_RANGE * rand:uniform())),
    case gen_udp:open(Attempt, [binary, {active,false}]) of
        {ok, Socket} -> {ok, Socket};
        _ -> find_udp_socket()
    end.




client_ntp_timestamp() ->
    {M, S, U} = os:timestamp(),
    
    BinU = <<(round(?USEC_FRAC(U))):32/integer>>,
    BinS = <<(M*1000000+S+?NTP_EPOCH_OFFSET):32/integer>>,
    
    <<BinS/binary, BinU/binary>>.

prepare_ntp_request() ->
    Time = client_ntp_timestamp(),
    
    Data = <<16#13,0,0,238,         %% V4 - Client - Microsecond Client Resolution
            0:160,            %% 3 DWORDs: Delay, Dispersion, Ref ID, Ref TS
            Time:8/binary,    %% Origin Timestamp (TS)
            0:128>>,        %% 4 DWORDS: Rx Timestamp, Tx Timestamp

    Key = crypto:strong_rand_bytes(4),
    Sig = crypto:hash(md5, <<Key/binary, Data/binary>>),
    
    <<Data/binary, Key/binary, Sig/binary>>.

generate_timestep() ->
    generate_timestep(0).

generate_timestep(Offset) ->
    {M, S, _} = os:timestamp(),
    round((M * 1000000+S+Offset) / 30).

totp(Secret, Step) -> 
    %% Create SHA-1 hash
    Hash = crypto:hmac(sha, Secret, <<Step:64/integer-unsigned>>),

    %% Determine dynamic offset
    %% Ignore that many bytes and store 4 bytes into THash
    Offset = 16#0f band binary:at(Hash,19),
    <<_:Offset/binary, THash:32/integer-unsigned, _/binary>> = Hash,

    %% Remove sign bit and create 6-digit code
    Code = (THash band 16#7fffffff) rem 1000000,
    lists:flatten(string:pad(integer_to_list(Code),6,leading,$0)).
