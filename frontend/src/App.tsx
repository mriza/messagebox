import { useState, useEffect, useRef } from 'react';
import { 
  GetProfiles, SaveProfile, DeleteProfile, ConnectMQTT, PublishMQTT,
  DisconnectMQTT, ConnectAMQP, StartConsumeAMQP, StopConsumeAMQP, PublishAMQP, DisconnectAMQP
} from '@wailsjs/go/main/App';
import { EventsOn } from '@wailsjs/runtime/runtime';
import { main } from '@wailsjs/go/models';

function App() {
  const [profiles, setProfiles] = useState<Record<string, main.Profile>>({});
  const [currentProfileName, setCurrentProfileName] = useState<string>('');
  
  const [protocol, setProtocol] = useState<'MQTT' | 'AMQP'>('MQTT');
  const [host, setHost] = useState('localhost');
  const [port, setPort] = useState('1883');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [useTLS, setUseTLS] = useState(false);
  
  const [mqttTopic, setMqttTopic] = useState('test/topic');
  // AMQP specific
  const [amqpUrl, setAmqpUrl] = useState('');
  const [amqpVhost, setAmqpVhost] = useState('/');
  const [amqpQueue, setAmqpQueue] = useState('');
  const [amqpExchange, setAmqpExchange] = useState('');
  const [amqpRouting, setAmqpRouting] = useState('');

  const [connected, setConnected] = useState(false);
  const [enableSender, setEnableSender] = useState(true);
  const [enableReceiver, setEnableReceiver] = useState(true);
  
  const [payload, setPayload] = useState('');
  const [sentLogs, setSentLogs] = useState<string[]>([]);
  const [receivedLogs, setReceivedLogs] = useState<string[]>([]);
  
  const sentLogsEndRef = useRef<HTMLDivElement>(null);
  const receivedLogsEndRef = useRef<HTMLDivElement>(null);

  const enableReceiverRef = useRef(enableReceiver);

  useEffect(() => {
    enableReceiverRef.current = enableReceiver;
  }, [enableReceiver]);

  useEffect(() => {
    if (protocol === 'AMQP') {
      const scheme = useTLS ? 'amqps' : 'amqp';
      const userPass = username || password ? `${encodeURIComponent(username)}:${encodeURIComponent(password)}@` : '';
      const vhostStr = amqpVhost ? `/${encodeURIComponent(amqpVhost.startsWith('/') ? amqpVhost.substring(1) : amqpVhost)}` : '/';
      const generatedUrl = `${scheme}://${userPass}${host}:${port}${vhostStr}`;
      setAmqpUrl(generatedUrl);
    }
  }, [host, port, username, password, amqpVhost, useTLS, protocol]);

  useEffect(() => {
    refreshProfiles();
    
    // Setup Wails Event Listener for logs
    EventsOn('log', (msg: string) => {
      if (msg.startsWith('[SEND]') || msg.includes('SENT')) {
        setSentLogs(prev => [...prev.slice(-99), msg]); // Keep last 100
      } else {
        if (enableReceiverRef.current) {
          setReceivedLogs(prev => [...prev.slice(-99), msg]);
        }
      }
    });
  }, []);

  useEffect(() => {
    sentLogsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [sentLogs]);

  useEffect(() => {
    receivedLogsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [receivedLogs]);

  const refreshProfiles = async () => {
    try {
      const data = await GetProfiles();
      setProfiles(data || {});
      if (Object.keys(data || {}).length > 0 && !currentProfileName) {
        setCurrentProfileName(Object.keys(data)[0]);
      }
    } catch (err) {
      console.error("Failed to load profiles", err);
    }
  };

  const loadProfile = () => {
    if (!currentProfileName || !profiles[currentProfileName]) return;
    const p = profiles[currentProfileName];
    setProtocol(p.protocol as 'MQTT'|'AMQP');
    setHost(p.host);
    setPort(p.port);
    setUsername(p.username);
    setPassword(p.password);
    setMqttTopic(p.mqtt_topic);
    setAmqpVhost(p.amqp_vhost || '/');
    setAmqpQueue(p.amqp_queue || '');
    setAmqpExchange(p.amqp_exchange || '');
    setAmqpRouting(p.amqp_routing || '');
    setUseTLS(p.use_tls || false);
    setAmqpUrl(p.amqp_url || '');
  };

  const saveProfile = async () => {
    const name = window.prompt("Enter profile name:");
    if (!name) return;
    
    const p = new main.Profile({
      name, protocol, host, port, username, password,
      mqtt_topic: mqttTopic,
      amqp_vhost: amqpVhost,
      amqp_queue: amqpQueue,
      amqp_exchange: amqpExchange,
      amqp_routing: amqpRouting,
      use_tls: useTLS,
      amqp_url: amqpUrl,
    });
    
    await SaveProfile(name, p);
    await refreshProfiles();
    setCurrentProfileName(name);
  };

  const deleteProfile = async () => {
    if (!currentProfileName) return;
    await DeleteProfile(currentProfileName);
    setCurrentProfileName('');
    await refreshProfiles();
  };

  const handleProtocolChange = (val: 'MQTT'|'AMQP', tlsState: boolean = useTLS) => {
    setProtocol(val);
    if (val === 'MQTT') {
      setPort(tlsState ? '8883' : '1883');
    } else {
      setPort(tlsState ? '5671' : '5672');
    }
  };

  const handleTLSChange = (checked: boolean) => {
    setUseTLS(checked);
    handleProtocolChange(protocol, checked);
  };

  const toggleConnect = async () => {
    if (connected) {
      try {
        if (protocol === 'MQTT') await DisconnectMQTT();
        else await DisconnectAMQP();
        setConnected(false);
        setReceivedLogs(prev => [...prev, "Disconnected."]);
      } catch(e) { console.error(e); }
      return;
    }

    try {
      if (protocol === 'MQTT') {
        await ConnectMQTT(host, port, username, password, mqttTopic, useTLS);
      } else {
        await ConnectAMQP(amqpUrl, amqpQueue);
        if (enableReceiver) await StartConsumeAMQP();
      }
      setConnected(true);
      setReceivedLogs(prev => [...prev, `Connected to ${protocol}`]);
    } catch (e: any) {
      alert("Connection Error: " + String(e));
      setConnected(false);
    }
  };

  const handleReceiverToggle = async (checked: boolean) => {
    setEnableReceiver(checked);
    if (connected && protocol === 'AMQP') {
        if (checked) await StartConsumeAMQP();
        else await StopConsumeAMQP();
    }
  };

  const sendPayload = async () => {
    if (!payload) return;
    try {
      if (protocol === 'MQTT') {
        await PublishMQTT(mqttTopic, payload);
      } else {
        await PublishAMQP(amqpExchange, amqpRouting, payload);
      }
    } catch(e: any) {
      alert("Failed to send: " + String(e));
    }
  };

  return (
    <div className="h-screen bg-base-200 p-4 font-sans text-base-content overflow-hidden flex flex-col">
      <header className="mb-4">
        <h1 className="text-3xl font-bold text-primary flex items-center gap-2">
          <span className="bg-neutral text-neutral-content p-2 rounded-lg">💬</span>
          MessageBox
        </h1>
        <p className="text-sm opacity-70">MQTT & AMQP Tester Tool</p>
      </header>

      <div className="flex-1 grid grid-cols-1 lg:grid-cols-2 gap-6 min-h-0 overflow-y-auto">
        {/* LEFT COLUMN: Settings */}
        <div className="flex flex-col gap-6">
          {/* Profile Card */}
          <div className="card bg-base-100 shadow-xl border border-base-300">
            <div className="card-body p-4">
              <h2 className="card-title text-lg mb-2">Profiles</h2>
              <div className="flex gap-2 items-center">
                <select 
                  className="select select-bordered flex-1 select-sm"
                  value={currentProfileName}
                  onChange={e => setCurrentProfileName(e.target.value)}
                >
                  <option disabled value="">Select profile</option>
                  {Object.keys(profiles).map(k => (
                    <option key={k} value={k}>{k}</option>
                  ))}
                </select>
                <button className="btn btn-primary btn-sm" onClick={loadProfile}>Load</button>
                <button className="btn btn-secondary btn-sm" onClick={saveProfile}>Save</button>
                <button className="btn btn-error btn-sm" onClick={deleteProfile}>Delete</button>
              </div>
            </div>
          </div>

          {/* Connection Card */}
          <div className="card bg-base-100 shadow-xl border border-base-300 flex-1">
            <div className="card-body p-4 flex flex-col gap-4">
              <h2 className="card-title text-lg">Connection Settings</h2>
              
              <div className="flex gap-2 w-full items-end">
                <div className="form-control flex-1">
                  <label className="label py-1"><span className="label-text font-semibold">Protocol</span></label>
                  <select className="select select-bordered select-sm w-full" value={protocol} onChange={e => handleProtocolChange(e.target.value as any)} disabled={connected}>
                    <option value="MQTT">MQTT</option>
                    <option value="AMQP">AMQP</option>
                  </select>
                </div>
                <div className="form-control">
                  <label className="label cursor-pointer py-1 flex flex-col items-center justify-center gap-1">
                    <span className="label-text text-xs">Use TLS</span>
                    <input type="checkbox" className="checkbox checkbox-sm checkbox-primary" checked={useTLS} onChange={e => handleTLSChange(e.target.checked)} disabled={connected} />
                  </label>
                </div>
              </div>

              <div className="flex gap-2 w-full">
                <div className="form-control flex-1">
                  <label className="label py-1"><span className="label-text">Host</span></label>
                  <input type="text" className="input input-bordered input-sm" value={host} onChange={e => setHost(e.target.value)} disabled={connected}/>
                </div>
                <div className="form-control w-24">
                  <label className="label py-1"><span className="label-text">Port</span></label>
                  <input type="text" className="input input-bordered input-sm" value={port} onChange={e => setPort(e.target.value)} disabled={connected}/>
                </div>
              </div>

              <div className="flex gap-2 w-full">
                <div className="form-control flex-1">
                  <label className="label py-1"><span className="label-text">Username</span></label>
                  <input type="text" className="input input-bordered input-sm" value={username} onChange={e => setUsername(e.target.value)} disabled={connected}/>
                </div>
                <div className="form-control flex-1">
                  <label className="label py-1"><span className="label-text">Password</span></label>
                  <input type="password" className="input input-bordered input-sm" value={password} onChange={e => setPassword(e.target.value)} disabled={connected}/>
                </div>
              </div>

              {protocol === 'AMQP' && (
                <div className="form-control mt-2">
                  <label className="label py-1"><span className="label-text font-semibold">Connection URL</span></label>
                  <input type="text" className="input input-bordered input-sm font-mono" value={amqpUrl} onChange={e => setAmqpUrl(e.target.value)} disabled={connected} placeholder="amqp://user:pass@host:port/vhost"/>
                </div>
              )}

              <div className="divider my-0"></div>

              {protocol === 'MQTT' ? (
                <div className="form-control">
                  <label className="label py-1"><span className="label-text">MQTT Topic</span></label>
                  <input type="text" className="input input-bordered input-sm" value={mqttTopic} onChange={e => setMqttTopic(e.target.value)} disabled={connected}/>
                </div>
              ) : (
                <>
                  <div className="flex gap-2 w-full">
                    <div className="form-control w-1/3">
                      <label className="label py-1"><span className="label-text">VHost</span></label>
                      <input type="text" className="input input-bordered input-sm" value={amqpVhost} onChange={e => setAmqpVhost(e.target.value)} disabled={connected}/>
                    </div>
                    <div className="form-control flex-1">
                      <label className="label py-1"><span className="label-text">Queue</span></label>
                      <input type="text" className="input input-bordered input-sm" value={amqpQueue} onChange={e => setAmqpQueue(e.target.value)} disabled={connected}/>
                    </div>
                  </div>
                  <div className="flex gap-2 w-full">
                    <div className="form-control flex-1">
                      <label className="label py-1"><span className="label-text">Exchange</span></label>
                      <input type="text" className="input input-bordered input-sm" value={amqpExchange} onChange={e => setAmqpExchange(e.target.value)} disabled={connected}/>
                    </div>
                    <div className="form-control flex-1">
                      <label className="label py-1"><span className="label-text">Routing Key</span></label>
                      <input type="text" className="input input-bordered input-sm" value={amqpRouting} onChange={e => setAmqpRouting(e.target.value)} disabled={connected}/>
                    </div>
                  </div>
                </>
              )}

              <div className="mt-auto pt-4 flex justify-end">
                <button className={`btn btn-block ${connected ? 'btn-error' : 'btn-success'}`} onClick={toggleConnect}>
                  {connected ? 'Disconnect' : 'Connect'}
                </button>
              </div>

            </div>
          </div>
        </div>

        {/* RIGHT COLUMN: Sender & Receiver */}
        <div className="flex flex-col gap-6 h-full min-h-0">
          {/* Sender */}
          <div className="card bg-base-100 shadow-xl border border-base-300 flex-1 flex flex-col min-h-0">
            <div className="card-body p-4 flex flex-col gap-2 min-h-0">
              <div className="flex justify-between items-center mb-1">
                <h2 className="card-title text-lg m-0">Sender</h2>
                <div className="form-control">
                  <label className="cursor-pointer label p-0 gap-2">
                    <span className="label-text text-xs">Enable</span> 
                    <input type="checkbox" className="toggle toggle-primary toggle-sm" checked={enableSender} onChange={e => setEnableSender(e.target.checked)} disabled={!connected}/>
                  </label>
                </div>
              </div>
              
              <div className="flex gap-2">
                <input 
                  type="text" 
                  placeholder="Payload..." 
                  className="input input-bordered input-sm flex-1" 
                  value={payload} 
                  onChange={e => setPayload(e.target.value)} 
                  disabled={!connected || !enableSender}
                  onKeyDown={e => e.key === 'Enter' && sendPayload()}
                />
                <button className="btn btn-primary btn-sm" onClick={sendPayload} disabled={!connected || !enableSender}>Send</button>
              </div>

              <div className="bg-neutral text-neutral-content p-2 rounded-lg text-xs font-mono overflow-y-auto flex-1 min-h-0 mt-2">
                {sentLogs.map((log, i) => (
                  <div key={i} className="mb-1 text-info">{log}</div>
                ))}
                <div ref={sentLogsEndRef} />
              </div>
            </div>
          </div>

          {/* Receiver */}
          {/* Receiver */}
          <div className="card bg-base-100 shadow-xl border border-base-300 flex-1 flex flex-col min-h-0">
            <div className="card-body p-4 flex flex-col gap-2 min-h-0">
              <div className="flex justify-between items-center mb-1">
                <h2 className="card-title text-lg m-0">Receiver</h2>
                <div className="form-control">
                  <label className="cursor-pointer label p-0 gap-2">
                    <span className="label-text text-xs">Enable</span> 
                    <input type="checkbox" className="toggle toggle-secondary toggle-sm" checked={enableReceiver} onChange={e => handleReceiverToggle(e.target.checked)} disabled={!connected}/>
                  </label>
                </div>
              </div>

              <div className="bg-neutral text-neutral-content p-2 rounded-lg text-xs font-mono overflow-y-auto flex-1 min-h-0">
                 {receivedLogs.map((log, i) => (
                  <div key={i} className="mb-1 text-success">{log}</div>
                ))}
                <div ref={receivedLogsEndRef} />
              </div>
            </div>
          </div>

        </div>
      </div>
    </div>
  )
}

export default App
