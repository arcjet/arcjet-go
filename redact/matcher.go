package redact

// replacementMatcher finds replacement texts in a string. The texts share one
// prefix tree, so each position costs at most the length of the longest text,
// however many texts share a prefix such as "<Redacted".
type replacementMatcher struct {
	root *trieNode
}

type trieNode struct {
	children map[byte]*trieNode
	text     string // the replacement that ends here, or "" for none
}

type replacementMatch struct {
	start int
	text  string
}

// newReplacementMatcher builds a matcher for texts. Empty texts are ignored.
func newReplacementMatcher(texts []string) *replacementMatcher {
	root := &trieNode{children: map[byte]*trieNode{}}
	for _, text := range texts {
		if text == "" {
			continue
		}
		node := root
		for i := range len(text) {
			child, ok := node.children[text[i]]
			if !ok {
				child = &trieNode{children: map[byte]*trieNode{}}
				node.children[text[i]] = child
			}
			node = child
		}
		node.text = text
	}
	return &replacementMatcher{root: root}
}

// find returns every occurrence in value, left to right and without overlaps.
// At each position the longest text wins, so a replacement that contains
// another is found whole.
func (m *replacementMatcher) find(value string) []replacementMatch {
	var matches []replacementMatch
	for i := 0; i < len(value); {
		node := m.root
		found := ""
		for j := i; j < len(value); j++ {
			next, ok := node.children[value[j]]
			if !ok {
				break
			}
			node = next
			if node.text != "" {
				found = node.text
			}
		}
		if found == "" {
			i++
			continue
		}
		matches = append(matches, replacementMatch{start: i, text: found})
		i += len(found)
	}
	return matches
}
