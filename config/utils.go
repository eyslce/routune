package config

import (
	"fmt"
	"strings"

	"github.com/eyslce/clash/adapter/outboundgroup"
	"github.com/eyslce/clash/common/structure"
)

// trimArr 函数接收一个字符串切片，并返回一个新的字符串切片，
// 其中每个元素的左右空格都被移除。
func trimArr(arr []string) (r []string) {
	for _, e := range arr { // 遍历输入切片中的每个字符串。
		r = append(r, strings.Trim(e, " ")) // 使用strings.Trim移除字符串两边的空格，并将结果追加到新切片r。
	}
	return // 返回处理后的新切片。
}

// proxyGroupsDagSort 函数检查代理组配置是否形成一个有向无环图 (DAG)，
// 并根据依赖关系对所有代理组进行拓扑排序。
// 同时，它会保留代理组在原始配置文件中的索引信息（通过直接修改输入groupsConfig的顺序实现）。
// 如果检测到循环依赖，则返回一个错误，指出循环中涉及的代理组。
// Check if ProxyGroups form DAG(Directed Acyclic Graph), and sort all ProxyGroups by dependency order.
// Meanwhile, record the original index in the config file.
// If loop is detected, return an error with location of loop.
func proxyGroupsDagSort(groupsConfig []map[string]any) error {
	// graphNode 结构体用于在拓扑排序过程中表示图中的节点。
	type graphNode struct {
		indegree int // indegree 表示节点的入度，即有多少其他节点指向它。
		// topological order (not used in current logic directly for sorting, sorting is done by rearranging groupsConfig)
		topo int // topo 原意为拓扑顺序，在此处未直接用于排序结果的索引，排序通过修改groupsConfig实现。
		// the original data in `groupsConfig`
		data map[string]any // data 存储了该节点对应的原始代理组配置映射。
		// `outdegree` and `from` are used in loop locating
		outdegree int                              // outdegree 表示节点的出度，用于检测循环时的反向遍历。
		option    *outboundgroup.GroupCommonOption // option 存储了解析后的代理组基本选项。
		from      []string                         // from 存储了所有指向当前节点的其他节点的名称，用于检测循环时的路径回溯。
	}

	// 使用structure.NewDecoder进行弱类型解码，主要用于解析代理组的名称和其包含的代理列表。
	decoder := structure.NewDecoder(structure.Option{TagName: "group", WeaklyTypedInput: true})
	graph := make(map[string]*graphNode) // graph 用于存储依赖关系图，键是代理或代理组的名称。

	// 步骤 1.1: 构建依赖图
	// Step 1.1 build dependency graph
	for _, mapping := range groupsConfig { // 遍历原始配置文件中的每个代理组配置。
		option := &outboundgroup.GroupCommonOption{}
		// 解析代理组的基本选项，主要是为了获取组名和其引用的代理/子组列表。
		if err := decoder.Decode(mapping, option); err != nil {
			return fmt.Errorf("ProxyGroup %s: %s", option.Name, err.Error()) // 解析失败则返回错误。
		}

		groupName := option.Name
		// 更新或创建当前代理组的节点信息。
		if node, ok := graph[groupName]; ok { // 如果图中已存在该名称的节点 (可能之前作为其他组的子代理被添加)。
			if node.data != nil { // 如果data不为nil，说明之前已经处理过同名代理组，存在重复定义。
				return fmt.Errorf("ProxyGroup %s: duplicate group name", groupName)
			}
			node.data = mapping  // 设置节点的原始数据。
			node.option = option // 设置节点的解析后选项。
		} else { // 如果图中不存在该节点，则新建一个。
			graph[groupName] = &graphNode{0, -1, mapping, 0, option, nil}
		}

		// 遍历该代理组引用的所有代理或子组。
		for _, proxy := range option.Proxies {
			// 对于每个被引用的代理/子组，增加其入度。
			if node, ex := graph[proxy]; ex {
				node.indegree++
			} else {
				// 如果被引用的节点不存在于图中，则新建一个占位节点，并设置其入度为1。
				graph[proxy] = &graphNode{1, -1, nil, 0, nil, nil}
			}
		}
	}
	// Step 1.2 Topological Sort
	// topological index of **ProxyGroup** (used to place sorted groups back into groupsConfig from the end)
	index := 0                 // index 用于记录已排序的代理组数量，从groupsConfig末尾开始填充。
	queue := make([]string, 0) // queue 存储所有入度为0的节点名称。

	// 初始化队列，将所有入度为0的节点加入队列。
	for name, node := range graph {
		// in the beginning, put nodes that have `node.indegree == 0` into queue.
		if node.indegree == 0 {
			queue = append(queue, name)
		}
	}

	// 当队列不为空时，持续进行拓扑排序。
	// every element in queue have indegree == 0
	for ; len(queue) > 0; queue = queue[1:] { // 从队列中取出一个节点，并将其从队列中移除。
		name := queue[0]
		node := graph[name]

		// 只处理实际的代理组节点 (option不为nil)。占位符节点(如单个代理)会被忽略。
		if node.option != nil {
			index++
			// 将已排序的代理组数据放回groupsConfig的末尾，实现逆序拓扑排序。
			// 这是因为后续解析代理组时，依赖的组需要先被解析。
			groupsConfig[len(groupsConfig)-index] = node.data

			// 如果该代理组不依赖任何其他代理/子组，则可以从图中删除它。
			if len(node.option.Proxies) == 0 {
				delete(graph, name)
				continue
			}

			// 遍历当前节点的所有出边 (其引用的代理/子组)。
			for _, proxy := range node.option.Proxies {
				child := graph[proxy]
				child.indegree-- // 将子节点的入度减1。
				// 如果子节点的入度变为0，则将其加入队列。
				if child.indegree == 0 {
					queue = append(queue, proxy)
				}
			}
		}
		delete(graph, name) // 处理完一个节点后，将其从图中删除。
	}

	// 如果排序后图中没有剩余节点，说明没有循环依赖，排序成功。
	// no loop is detected, return sorted ProxyGroup
	if len(graph) == 0 {
		return nil
	}

	// 如果图中仍有节点剩余，说明存在循环依赖。
	// if loop is detected, locate the loop and throw an error

	// 步骤 2.1: 重建图，填充出度和来源信息，用于定位循环。
	// Step 2.1 rebuild the graph, fill `outdegree` and `from` filed
	for name, node := range graph { // 遍历图中剩余的节点 (这些节点都处于循环中)。
		if node.option == nil { // 跳过非代理组节点 (理论上此时不应存在)。
			continue
		}

		if len(node.option.Proxies) == 0 { // 跳过没有出边的代理组节点 (理论上不应在循环中)。
			continue
		}

		// 为节点计算出度，并记录其被哪些节点引用 (from)。
		for _, proxy := range node.option.Proxies {
			node.outdegree++
			child := graph[proxy]
			if child.from == nil {
				child.from = make([]string, 0, child.indegree) // 初始化from切片。
			}
			child.from = append(child.from, name) // 添加来源节点。
		}
	}
	// Step 2.2 remove nodes outside the loop. so that we have only the loops remain in `graph`
	queue = make([]string, 0) // 重新初始化队列。

	// 将所有出度为0的节点加入队列。
	// initialize queue with node have outdegree == 0
	for name, node := range graph {
		if node.outdegree == 0 {
			queue = append(queue, name)
		}
	}

	// 当队列不为空时，持续移除出度为0的节点。
	// every element in queue have outdegree == 0
	for ; len(queue) > 0; queue = queue[1:] {
		name := queue[0]
		node := graph[name]
		// 对于当前移除节点的所有来源节点 (父节点)，将其出度减1。
		for _, f := range node.from {
			graph[f].outdegree--
			// 如果父节点的出度也变为0，则将其加入队列。
			if graph[f].outdegree == 0 {
				queue = append(queue, f)
			}
		}
		delete(graph, name) // 从图中删除当前节点。
	}
	// Step 2.3 report the elements in loop
	loopElements := make([]string, 0, len(graph)) // 用于存储循环中的所有节点名称。
	for name := range graph {                     // 此时图中剩下的所有节点都属于循环。
		loopElements = append(loopElements, name)
		delete(graph, name) // 清空图。
	}
	return fmt.Errorf("loop is detected in ProxyGroup, please check following ProxyGroups: %v", loopElements)
}
