# for y in dv:
    #     min_dist = float("inf")
    #     min_neighbor = None
    #     for neighbor in self.neighbor_dvs:
    #         print(self.neighbor_dvs[neighbor])
    #         if self.neighbor_dvs[neighbor].get(y):

    #             curr_cost = 1 + self.neighbor_dvs[neighbor][y]
    #             if curr_cost < min_dist:
    #                 min_dist = curr_cost
    #                 min_neighbor = neighbor

    #     if min_neighbor:
    #         forwarding_table[y] = min_neighbor # TODO: figure out if this is what I do 
    #     if min_neighbor:
    #        dv[y] = min_dist