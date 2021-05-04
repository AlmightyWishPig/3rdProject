function correlation(data)
    for i = 1:size(data,1)
        data1 = data(i,:)';
        for j = 1:size(data,1)
            data2 = data(j,:)';
            dataX2 = [data1, interp1(data2(:,1), data2(:,2), data1, 'linear', 'extrap')];
        end
    end