package headscale

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const reservedResponseHeaderSize = 4

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(ctx *gin.Context) {
	ctx.Data(
		http.StatusOK,
		"text/plain; charset=utf-8",
		[]byte(h.publicKey.String()[5:]),
	)
}

// RegisterWebAPI shows a simple message in the browser to point to the CLI
// Listens in /register.
func (h *Headscale) RegisterWebAPI(ctx *gin.Context) {
	machineKeyStr := ctx.Query("key")
	if machineKeyStr == "" {
		ctx.String(http.StatusBadRequest, "Wrong params")

		return
	}

	ctx.Data(http.StatusOK, "text/html; charset=utf-8", []byte(fmt.Sprintf(`
	<html>
	<body>
	<h1>headscale</h1>
	<p>
		Run the command below in the headscale server to add this machine to your network:
	</p>

	<p>
		<code>
			<b>headscale -n NAMESPACE nodes register --key %s</b>
		</code>
	</p>

	</body>
	</html>

	`, machineKeyStr)))
}

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:id.
func (h *Headscale) RegistrationHandler(ctx *gin.Context) {
	body, _ := io.ReadAll(ctx.Request.Body)
	machineKeyStr := ctx.Param("id")
	machineKey, err := ParseMachineKey(machineKeyStr)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		ctx.String(http.StatusInternalServerError, "Sad!")

		return
	}
	req := tailcfg.RegisterRequest{}
	err = decode(body, &req, machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "Registration").
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		ctx.String(http.StatusInternalServerError, "Very sad!")

		return
	}

	now := time.Now().UTC()
	machine, err := h.GetMachineByMachineKey(machineKey.String())
	if errors.Is(err, gorm.ErrRecordNotFound) {
		log.Info().Str("machine", req.Hostinfo.Hostname).Msg("New machine")
		newMachine := Machine{
			Expiry:     &time.Time{},
			MachineKey: machineKey.String(),
			Name:       req.Hostinfo.Hostname,
		}
		if err := h.db.Create(&newMachine).Error; err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Could not create row")
			machineRegistrations.WithLabelValues("unknown", "web", "error", machine.Namespace.Name).
				Inc()

			return
		}
		machine = &newMachine
	}

	if !machine.Registered && req.Auth.AuthKey != "" {
		h.handleAuthKey(ctx, h.db, machineKey, req, *machine)

		return
	}

	resp := tailcfg.RegisterResponse{}

	// We have the updated key!
	if machine.NodeKey == key.NodePublic(req.NodeKey).String() {
		// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
		//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
		if !req.Expiry.IsZero() && req.Expiry.UTC().Before(now) {
			log.Info().
				Str("handler", "Registration").
				Str("machine", machine.Name).
				Msg("Client requested logout")

			machine.Expiry = &req.Expiry // save the expiry so that the machine is marked as expired
			h.db.Save(&machine)

			resp.AuthURL = ""
			resp.MachineAuthorized = false
			resp.User = *machine.Namespace.toUser()
			respBody, err := encode(resp, machineKey, h.privateKey)
			if err != nil {
				log.Error().
					Str("handler", "Registration").
					Err(err).
					Msg("Cannot encode message")
				ctx.String(http.StatusInternalServerError, "")

				return
			}
			ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

			return
		}

		if machine.Registered && machine.Expiry.UTC().After(now) {
			// The machine registration is valid, respond with redirect to /map
			log.Debug().
				Str("handler", "Registration").
				Str("machine", machine.Name).
				Msg("Client is registered and we have the current NodeKey. All clear to /map")

			resp.AuthURL = ""
			resp.MachineAuthorized = true
			resp.User = *machine.Namespace.toUser()
			resp.Login = *machine.Namespace.toLogin()

			respBody, err := encode(resp, machineKey, h.privateKey)
			if err != nil {
				log.Error().
					Str("handler", "Registration").
					Err(err).
					Msg("Cannot encode message")
				machineRegistrations.WithLabelValues("update", "web", "error", machine.Namespace.Name).
					Inc()
				ctx.String(http.StatusInternalServerError, "")

				return
			}
			machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
				Inc()
			ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

			return
		}

		// The client has registered before, but has expired
		log.Debug().
			Str("handler", "Registration").
			Str("machine", machine.Name).
			Msg("Machine registration has expired.")
		h.needsAuth(ctx, &req, &resp, machine, machineKey)

		return
	}

	// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
	if machine.NodeKey == key.NodePublic(req.OldNodeKey).String() &&
		machine.Expiry.UTC().After(now) {
		log.Debug().
			Str("handler", "Registration").
			Str("machine", machine.Name).
			Msg("We have the OldNodeKey in the database. This is a key refresh")
		machine.NodeKey = key.NodePublic(req.NodeKey).String()
		h.db.Save(&machine)

		resp.AuthURL = ""
		resp.User = *machine.Namespace.toUser()
		respBody, err := encode(resp, machineKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			ctx.String(http.StatusInternalServerError, "Extremely sad!")

			return
		}
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)

		return
	}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Str("handler", "Registration").
		Str("machine", machine.Name).
		Msg("The node is sending us a new NodeKey")
	h.needsAuth(ctx, &req, &resp, machine, machineKey)
}

func (h *Headscale) needsAuth(
	ctx *gin.Context,
	req *tailcfg.RegisterRequest,
	resp *tailcfg.RegisterResponse,
	machine *Machine,
	machineKey key.MachinePublic,
) {
	if req.Auth.AuthKey != "" {
		h.handleAuthKey(ctx, h.db, machineKey, *req, *machine)
	} else {
		log.Debug().
			Str("handler", "Registration").
			Str("machine", machine.Name).
			Msg("Sending a authurl to register")

		if h.cfg.OIDC.Issuer != "" {
			resp.AuthURL = fmt.Sprintf(
				"%s/oidc/register/%s",
				strings.TrimSuffix(h.cfg.ServerURL, "/"),
				machineKey.String(),
			)
		} else {
			resp.AuthURL = fmt.Sprintf(
				"%s/register?key=%s",
				strings.TrimSuffix(h.cfg.ServerURL, "/"), 
				machineKey.String(),
			)
		}
		// save the requested expiry time for retrieval later in the authentication flow
		machine.RequestedExpiry = &req.Expiry
		// save the NodeKey
		machine.NodeKey = key.NodePublic(req.NodeKey).String() 
		h.db.Save(&machine)

		respBody, err := encode(resp, machineKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("handler", "Registration").
				Err(err).
				Msg("Cannot encode message")
			ctx.String(http.StatusInternalServerError, "")
	
			return
		}
		machineRegistrations.WithLabelValues("new", "web", "success", machine.Namespace.Name).
			Inc()
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
	}
}

func (h *Headscale) getMapResponse(
	machineKey key.MachinePublic,
	req tailcfg.MapRequest,
	machine *Machine,
) ([]byte, error) {
	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := machine.toNode(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot convert to node")

		return nil, err
	}

	peers, err := h.getPeers(machine)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	profiles := getMapResponseUserProfiles(*machine, peers)

	nodePeers, err := peers.toNodes(h.cfg.BaseDomain, h.cfg.DNSConfig, true)
	if err != nil {
		log.Error().
			Str("func", "getMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")

		return nil, err
	}

	dnsConfig := getMapResponseDNSConfig(
		h.cfg.DNSConfig,
		h.cfg.BaseDomain,
		*machine,
		peers,
	)

	resp := tailcfg.MapResponse{
		KeepAlive:    false,
		Node:         node,
		Peers:        nodePeers,
		DNSConfig:    dnsConfig,
		Domain:       h.cfg.BaseDomain,
		PacketFilter: h.aclRules,
		DERPMap:      h.DERPMap,
		UserProfiles: profiles,
	}

	log.Trace().
		Str("func", "getMapResponse").
		Str("machine", req.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	var respBody []byte
	if req.Compress == "zstd" {
		src, _ := json.Marshal(resp)
		log.Debug().
			Str("func", "getMapResponse").
			Bytes("mapResponse", src).
			Msg("Map response to be sent to tailscale client.")

		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody, err = encodeMsg(srcCompressed, machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	} else {
		respBody, err = encode(resp, machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	// declare the incoming size on the first 4 bytes
	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) getMapKeepAliveResponse(
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
) ([]byte, error) {
	mapResponse := tailcfg.MapResponse{
		KeepAlive: true,
	}
	var respBody []byte
	var err error
	if mapRequest.Compress == "zstd" {
		src, _ := json.Marshal(mapResponse)
		encoder, _ := zstd.NewWriter(nil)
		srcCompressed := encoder.EncodeAll(src, nil)
		respBody, err = encodeMsg(srcCompressed, machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	} else {
		respBody, err = encode(mapResponse, machineKey, h.privateKey)
		if err != nil {
			return nil, err
		}
	}
	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func (h *Headscale) handleAuthKey(
	ctx *gin.Context,
	db *gorm.DB,
	idKey key.MachinePublic,
	reqisterRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", reqisterRequest.Hostinfo.Hostname).
		Msgf("Processing auth key for %s", reqisterRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}
	pak, err := h.checkKeyValidity(reqisterRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", machine.Name).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false
		respBody, err := encode(resp, idKey, h.privateKey)
		if err != nil {
			log.Error().
				Str("func", "handleAuthKey").
				Str("machine", machine.Name).
				Err(err).
				Msg("Cannot encode message")
			ctx.String(http.StatusInternalServerError, "")
			machineRegistrations.WithLabelValues("new", "authkey", "error", machine.Namespace.Name).
				Inc()

			return
		}
		ctx.Data(http.StatusUnauthorized, "application/json; charset=utf-8", respBody)
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", machine.Name).
			Msg("Failed authentication via AuthKey")
		machineRegistrations.WithLabelValues("new", "authkey", "error", machine.Namespace.Name).
			Inc()

		return
	}

	log.Debug().
		Str("func", "handleAuthKey").
		Str("machine", machine.Name).
		Msg("Authentication key was valid")
	machine.AuthKeyID = uint(pak.ID)

	if machine.IPAddress == "" {
		log.Debug().
			Str("func", "handleAuthKey").
			Str("machine", machine.Name).
			Msg("Acquiring an IP address")

		ip, err := h.getAvailableIP()
		if err != nil {
			log.Error().
				Str("func", "handleAuthKey").
				Str("machine", machine.Name).
				Msg("Failed to find an available IP")
			machineRegistrations.WithLabelValues("new", "authkey", "error", machine.Namespace.Name).
				Inc()
	
			return
		}

		log.Info().
			Str("func", "handleAuthKey").
			Str("machine", machine.Name).
			Str("ip", ip.String()).
			Msgf("Assigning %s to %s", ip, machine.Name)
		machine.IPAddress = ip.String()
	}

	machine.NamespaceID = pak.NamespaceID
	machine.Registered = true
	machine.RegisterMethod = "authKey"
	machine.RequestedExpiry = nil
	machine.Expiry = &reqisterRequest.Expiry
	machine.NodeKey = key.NodePublic(reqisterRequest.NodeKey).String()
	db.Save(&machine)

	pak.Used = true
	db.Save(&pak)

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	resp.Login = *machine.Namespace.toLogin()

	respBody, err := encode(resp, idKey, h.privateKey)	
	if err != nil {
		log.Error().
			Str("func", "handleAuthKey").
			Str("machine", machine.Name).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", "authkey", "error", machine.Namespace.Name).
			Inc()
		ctx.String(http.StatusInternalServerError, "Extremely sad!")

		return
	}
	machineRegistrations.WithLabelValues("new", "authkey", "success", machine.Namespace.Name).
		Inc()
	ctx.Data(http.StatusOK, "application/json; charset=utf-8", respBody)
	log.Info().
		Str("func", "handleAuthKey").
		Str("machine", machine.Name).
		Str("ip", machine.IPAddress).
		Msg("Successfully authenticated via AuthKey")
}
