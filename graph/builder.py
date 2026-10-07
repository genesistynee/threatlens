def build_attack_graph(events):
    """
    Build an entity relationship graph from security events.
    """

    nodes = []
    edges = []

    seen_nodes = set()
    seen_edges = set()

    def add_node(node_id, node_type):
        key = (node_id, node_type)

        if node_id and key not in seen_nodes:
            nodes.append({
                "id": node_id,
                "type": node_type
            })
            seen_nodes.add(key)

    def add_edge(source, target, relationship):
        key = (source, target, relationship)

        if (
            source
            and target
            and key not in seen_edges
        ):
            edges.append({
                "source": source,
                "target": target,
                "relationship": relationship
            })
            seen_edges.add(key)

    for event in events:

        user_id = event.get("user_id")
        device_id = event.get("device_id")
        src_ip = event.get("src_ip")
        resource = event.get("resource")
        destination = event.get("destination")

        # --------------------------------------------------
        # USER
        # --------------------------------------------------

        if user_id:
            add_node(user_id, "user")

        # --------------------------------------------------
        # DEVICE
        # --------------------------------------------------

        if device_id:
            add_node(device_id, "device")

            if user_id:
                add_edge(
                    user_id,
                    device_id,
                    "uses"
                )

        # --------------------------------------------------
        # IP ADDRESS
        # --------------------------------------------------

        if src_ip:
            add_node(src_ip, "ip")

            if user_id:
                add_edge(
                    user_id,
                    src_ip,
                    "logs in from"
                )

        # --------------------------------------------------
        # FILE
        # --------------------------------------------------

        if (
            event.get("event_type") == "FILE_ACCESS"
            and resource
        ):
            add_node(resource, "file")

            if device_id:
                add_edge(
                    device_id,
                    resource,
                    "accesses"
                )

        # --------------------------------------------------
        # USB DEVICE
        # --------------------------------------------------

        if (
            event.get("event_type") == "USB"
            and resource
        ):
            add_node(resource, "usb")

            if device_id:
                add_edge(
                    device_id,
                    resource,
                    "connects"
                )

        # --------------------------------------------------
        # FILE TRANSFER
        # --------------------------------------------------

        if (
            event.get("event_type") == "FILE_TRANSFER"
            and resource
            and destination
        ):
            add_node(resource, "file")
            add_node(destination, "usb")

            add_edge(
                resource,
                destination,
                "copied to"
            )

    return {
        "nodes": nodes,
        "edges": edges
    }